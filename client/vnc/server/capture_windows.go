//go:build windows

package server

import (
	"fmt"
	"image"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")
	user32 = windows.NewLazySystemDLL("user32.dll")

	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procCreateCompatDC   = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection = gdi32.NewProc("CreateDIBSection")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procDeleteDC         = gdi32.NewProc("DeleteDC")
	procBitBlt           = gdi32.NewProc("BitBlt")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")

	// Desktop switching for service/Session 0 capture.
	procOpenInputDesktop          = user32.NewProc("OpenInputDesktop")
	procSetThreadDesktop          = user32.NewProc("SetThreadDesktop")
	procCloseDesktop              = user32.NewProc("CloseDesktop")
	procOpenWindowStation         = user32.NewProc("OpenWindowStationW")
	procSetProcessWindowStation   = user32.NewProc("SetProcessWindowStation")
	procCloseWindowStation        = user32.NewProc("CloseWindowStation")
	procGetUserObjectInformationW = user32.NewProc("GetUserObjectInformationW")
)

const uoiName = 2

const (
	smCxScreen   = 0
	smCyScreen   = 1
	srccopy      = 0x00CC0020
	dibRgbColors = 0
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
}

// setupInteractiveWindowStation associates the current process with WinSta0,
// the interactive window station. This is required for a SYSTEM service in
// Session 0 to call OpenInputDesktop for screen capture and input injection.
func setupInteractiveWindowStation() error {
	name, err := windows.UTF16PtrFromString("WinSta0")
	if err != nil {
		return fmt.Errorf("UTF16 WinSta0: %w", err)
	}
	hWinSta, _, err := procOpenWindowStation.Call(
		uintptr(unsafe.Pointer(name)),
		0,
		uintptr(windows.MAXIMUM_ALLOWED),
	)
	if hWinSta == 0 {
		return fmt.Errorf("OpenWindowStation(WinSta0): %w", err)
	}
	r, _, err := procSetProcessWindowStation.Call(hWinSta)
	if r == 0 {
		procCloseWindowStation.Call(hWinSta)
		return fmt.Errorf("SetProcessWindowStation: %w", err)
	}
	log.Info("process window station set to WinSta0 (interactive)")
	return nil
}

func screenSize() (int, int) {
	w, _, _ := procGetSystemMetrics.Call(uintptr(smCxScreen))
	h, _, _ := procGetSystemMetrics.Call(uintptr(smCyScreen))
	return int(w), int(h)
}

func getDesktopName(hDesk uintptr) string {
	var buf [256]uint16
	var needed uint32
	procGetUserObjectInformationW.Call(hDesk, uoiName,
		uintptr(unsafe.Pointer(&buf[0])), 512,
		uintptr(unsafe.Pointer(&needed)))
	return windows.UTF16ToString(buf[:])
}

// switchToInputDesktop opens the desktop currently receiving user input
// and sets it as the calling OS thread's desktop. Must be called from a
// goroutine locked to its OS thread via runtime.LockOSThread().
func switchToInputDesktop() (bool, string) {
	hDesk, _, _ := procOpenInputDesktop.Call(0, 0, uintptr(windows.MAXIMUM_ALLOWED))
	if hDesk == 0 {
		return false, ""
	}
	name := getDesktopName(hDesk)
	ret, _, _ := procSetThreadDesktop.Call(hDesk)
	procCloseDesktop.Call(hDesk)
	return ret != 0, name
}

// gdiCapturer captures the desktop screen using GDI BitBlt.
// GDI objects (DC, DIBSection) are allocated once and reused across frames.
type gdiCapturer struct {
	mu     sync.Mutex
	width  int
	height int

	// Pre-allocated GDI resources, reused across captures.
	memDC uintptr
	bmp   uintptr
	bits  uintptr
}

func newGDICapturer() (*gdiCapturer, error) {
	w, h := screenSize()
	if w == 0 || h == 0 {
		return nil, fmt.Errorf("screen dimensions are zero")
	}
	c := &gdiCapturer{width: w, height: h}
	if err := c.allocGDI(); err != nil {
		return nil, err
	}
	return c, nil
}

// allocGDI pre-allocates the compatible DC and DIB section for reuse.
func (c *gdiCapturer) allocGDI() error {
	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return fmt.Errorf("GetDC returned 0")
	}
	defer procReleaseDC.Call(0, screenDC)

	memDC, _, _ := procCreateCompatDC.Call(screenDC)
	if memDC == 0 {
		return fmt.Errorf("CreateCompatibleDC returned 0")
	}

	bi := bitmapInfo{
		Header: bitmapInfoHeader{
			Size:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			Width:    int32(c.width),
			Height:   -int32(c.height), // negative = top-down DIB
			Planes:   1,
			BitCount: 32,
		},
	}

	var bits uintptr
	bmp, _, _ := procCreateDIBSection.Call(
		screenDC,
		uintptr(unsafe.Pointer(&bi)),
		dibRgbColors,
		uintptr(unsafe.Pointer(&bits)),
		0, 0,
	)
	if bmp == 0 || bits == 0 {
		procDeleteDC.Call(memDC)
		return fmt.Errorf("CreateDIBSection returned 0")
	}

	procSelectObject.Call(memDC, bmp)

	c.memDC = memDC
	c.bmp = bmp
	c.bits = bits
	return nil
}

func (c *gdiCapturer) close() { c.freeGDI() }

// freeGDI releases pre-allocated GDI resources.
func (c *gdiCapturer) freeGDI() {
	if c.bmp != 0 {
		procDeleteObject.Call(c.bmp)
		c.bmp = 0
	}
	if c.memDC != 0 {
		procDeleteDC.Call(c.memDC)
		c.memDC = 0
	}
	c.bits = 0
}

func (c *gdiCapturer) capture() (*image.RGBA, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.memDC == 0 {
		return nil, fmt.Errorf("GDI resources not allocated")
	}

	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return nil, fmt.Errorf("GetDC returned 0")
	}
	defer procReleaseDC.Call(0, screenDC)

	ret, _, _ := procBitBlt.Call(c.memDC, 0, 0, uintptr(c.width), uintptr(c.height),
		screenDC, 0, 0, srccopy)
	if ret == 0 {
		return nil, fmt.Errorf("BitBlt returned 0")
	}

	n := c.width * c.height * 4
	raw := unsafe.Slice((*byte)(unsafe.Pointer(c.bits)), n)

	// GDI gives BGRA, the RFB encoder expects RGBA (img.Pix layout).
	// Swap R and B in bulk using uint32 operations (one load + mask + shift
	// per pixel instead of three separate byte assignments).
	img := image.NewRGBA(image.Rect(0, 0, c.width, c.height))
	pix := img.Pix
	copy(pix, raw)
	swizzleBGRAtoRGBA(pix)
	return img, nil
}

// DesktopCapturer captures the interactive desktop, handling desktop transitions
// (login screen, UAC prompts). A dedicated OS-locked goroutine continuously
// captures frames, which are retrieved by the VNC session on demand.
// Capture pauses automatically when no clients are connected.
type DesktopCapturer struct {
	mu    sync.Mutex
	frame *image.RGBA
	w, h  int

	// clients tracks the number of active VNC sessions. When zero, the
	// capture loop idles instead of grabbing frames.
	clients atomic.Int32

	// wake is signaled when a client connects and the loop should resume.
	wake chan struct{}
	// done is closed when Close is called, terminating the capture loop.
	done chan struct{}
}

// NewDesktopCapturer creates a capturer that continuously grabs the active desktop.
func NewDesktopCapturer() *DesktopCapturer {
	c := &DesktopCapturer{
		wake: make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	go c.loop()
	return c
}

// ClientConnect increments the active client count, resuming capture if needed.
func (c *DesktopCapturer) ClientConnect() {
	c.clients.Add(1)
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// ClientDisconnect decrements the active client count.
func (c *DesktopCapturer) ClientDisconnect() {
	c.clients.Add(-1)
}

// Close stops the capture loop and releases resources.
func (c *DesktopCapturer) Close() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}

// Width returns the current screen width.
func (c *DesktopCapturer) Width() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.w
}

// Height returns the current screen height.
func (c *DesktopCapturer) Height() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.h
}

// Capture returns the most recent desktop frame.
func (c *DesktopCapturer) Capture() (*image.RGBA, error) {
	c.mu.Lock()
	img := c.frame
	c.mu.Unlock()
	if img != nil {
		return img, nil
	}
	return nil, fmt.Errorf("no frame available yet")
}

// waitForClient blocks until a client connects or the capturer is closed.
func (c *DesktopCapturer) waitForClient() bool {
	if c.clients.Load() > 0 {
		return true
	}
	select {
	case <-c.wake:
		return true
	case <-c.done:
		return false
	}
}

func (c *DesktopCapturer) loop() {
	runtime.LockOSThread()

	// When running as a Windows service (Session 0), we need to attach to the
	// interactive window station before OpenInputDesktop will succeed.
	if err := setupInteractiveWindowStation(); err != nil {
		log.Warnf("attach to interactive window station: %v", err)
	}

	frameTicker := time.NewTicker(33 * time.Millisecond) // ~30 fps
	defer frameTicker.Stop()

	retryTimer := time.NewTimer(0)
	retryTimer.Stop()
	defer retryTimer.Stop()

	type frameCapturer interface {
		capture() (*image.RGBA, error)
		close()
	}

	var cap frameCapturer
	var desktopFails int
	var lastDesktop string

	createCapturer := func() (frameCapturer, error) {
		dc, err := newDXGICapturer()
		if err == nil {
			log.Info("using DXGI Desktop Duplication for capture")
			return dc, nil
		}
		log.Debugf("DXGI unavailable (%v), falling back to GDI", err)
		gc, err := newGDICapturer()
		if err != nil {
			return nil, err
		}
		log.Info("using GDI BitBlt for capture")
		return gc, nil
	}

	for {
		if !c.waitForClient() {
			if cap != nil {
				cap.close()
			}
			return
		}

		// No clients: release the capturer and wait.
		if c.clients.Load() <= 0 {
			if cap != nil {
				cap.close()
				cap = nil
			}
			continue
		}

		ok, desk := switchToInputDesktop()
		if !ok {
			desktopFails++
			if desktopFails == 1 || desktopFails%100 == 0 {
				log.Warnf("switchToInputDesktop failed (count=%d), no interactive desktop session?", desktopFails)
			}
			retryTimer.Reset(100 * time.Millisecond)
			select {
			case <-retryTimer.C:
			case <-c.done:
				return
			}
			continue
		}
		if desktopFails > 0 {
			log.Infof("switchToInputDesktop recovered after %d failures, desktop=%q", desktopFails, desk)
			desktopFails = 0
		}
		if desk != lastDesktop {
			log.Infof("desktop changed: %q -> %q", lastDesktop, desk)
			lastDesktop = desk
			if cap != nil {
				cap.close()
			}
			cap = nil
		}

		if cap == nil {
			fc, err := createCapturer()
			if err != nil {
				log.Warnf("create capturer: %v", err)
				retryTimer.Reset(500 * time.Millisecond)
				select {
				case <-retryTimer.C:
				case <-c.done:
					return
				}
				continue
			}
			cap = fc
			w, h := screenSize()
			c.mu.Lock()
			c.w, c.h = w, h
			c.mu.Unlock()
			log.Infof("screen capturer ready: %dx%d", w, h)
		}

		img, err := cap.capture()
		if err != nil {
			log.Debugf("capture: %v", err)
			cap.close()
			cap = nil
			retryTimer.Reset(100 * time.Millisecond)
			select {
			case <-retryTimer.C:
			case <-c.done:
				return
			}
			continue
		}

		c.mu.Lock()
		c.frame = img
		c.mu.Unlock()

		select {
		case <-frameTicker.C:
		case <-c.done:
			if cap != nil {
				cap.close()
			}
			return
		}
	}
}
