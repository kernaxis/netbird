//go:build darwin && !ios

package server

import (
	"fmt"
	"image"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"
)

var darwinCaptureOnce sync.Once

var (
	cgMainDisplayID                func() uint32
	cgDisplayPixelsWide            func(uint32) uintptr
	cgDisplayPixelsHigh            func(uint32) uintptr
	cgDisplayCreateImage           func(uint32) uintptr
	cgImageGetWidth                func(uintptr) uintptr
	cgImageGetHeight               func(uintptr) uintptr
	cgImageGetBytesPerRow          func(uintptr) uintptr
	cgImageGetBitsPerPixel         func(uintptr) uintptr
	cgImageGetDataProvider         func(uintptr) uintptr
	cgDataProviderCopyData         func(uintptr) uintptr
	cgImageRelease                 func(uintptr)
	cfDataGetLength                func(uintptr) int64
	cfDataGetBytePtr               func(uintptr) uintptr
	cfRelease                      func(uintptr)
	cgPreflightScreenCaptureAccess func() bool
	cgRequestScreenCaptureAccess   func() bool
	darwinCaptureReady             bool
)

func initDarwinCapture() {
	darwinCaptureOnce.Do(func() {
		cg, err := purego.Dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			log.Debugf("load CoreGraphics: %v", err)
			return
		}
		cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			log.Debugf("load CoreFoundation: %v", err)
			return
		}

		purego.RegisterLibFunc(&cgMainDisplayID, cg, "CGMainDisplayID")
		purego.RegisterLibFunc(&cgDisplayPixelsWide, cg, "CGDisplayPixelsWide")
		purego.RegisterLibFunc(&cgDisplayPixelsHigh, cg, "CGDisplayPixelsHigh")
		purego.RegisterLibFunc(&cgDisplayCreateImage, cg, "CGDisplayCreateImage")
		purego.RegisterLibFunc(&cgImageGetWidth, cg, "CGImageGetWidth")
		purego.RegisterLibFunc(&cgImageGetHeight, cg, "CGImageGetHeight")
		purego.RegisterLibFunc(&cgImageGetBytesPerRow, cg, "CGImageGetBytesPerRow")
		purego.RegisterLibFunc(&cgImageGetBitsPerPixel, cg, "CGImageGetBitsPerPixel")
		purego.RegisterLibFunc(&cgImageGetDataProvider, cg, "CGImageGetDataProvider")
		purego.RegisterLibFunc(&cgDataProviderCopyData, cg, "CGDataProviderCopyData")
		purego.RegisterLibFunc(&cgImageRelease, cg, "CGImageRelease")
		purego.RegisterLibFunc(&cfDataGetLength, cf, "CFDataGetLength")
		purego.RegisterLibFunc(&cfDataGetBytePtr, cf, "CFDataGetBytePtr")
		purego.RegisterLibFunc(&cfRelease, cf, "CFRelease")

		// Screen capture permission APIs (macOS 11+). Might not exist on older versions.
		if sym, err := purego.Dlsym(cg, "CGPreflightScreenCaptureAccess"); err == nil {
			purego.RegisterFunc(&cgPreflightScreenCaptureAccess, sym)
		}
		if sym, err := purego.Dlsym(cg, "CGRequestScreenCaptureAccess"); err == nil {
			purego.RegisterFunc(&cgRequestScreenCaptureAccess, sym)
		}

		darwinCaptureReady = true
	})
}

// CGCapturer captures the macOS main display using Core Graphics.
type CGCapturer struct {
	displayID uint32
	w, h      int
}

// NewCGCapturer creates a screen capturer for the main display.
func NewCGCapturer() (*CGCapturer, error) {
	initDarwinCapture()
	if !darwinCaptureReady {
		return nil, fmt.Errorf("CoreGraphics not available")
	}

	// Request Screen Recording permission (shows system dialog on macOS 11+).
	if cgPreflightScreenCaptureAccess != nil && !cgPreflightScreenCaptureAccess() {
		if cgRequestScreenCaptureAccess != nil {
			cgRequestScreenCaptureAccess()
		}
		log.Warn("Screen Recording permission not granted. " +
			"Grant in System Settings > Privacy & Security > Screen Recording, then restart.")
	}

	displayID := cgMainDisplayID()
	w := int(cgDisplayPixelsWide(displayID))
	h := int(cgDisplayPixelsHigh(displayID))
	if w == 0 || h == 0 {
		return nil, fmt.Errorf("display dimensions are zero")
	}

	log.Infof("macOS capturer ready: %dx%d (display=%d)", w, h, displayID)
	return &CGCapturer{displayID: displayID, w: w, h: h}, nil
}

// Width returns the screen width.
func (c *CGCapturer) Width() int { return c.w }

// Height returns the screen height.
func (c *CGCapturer) Height() int { return c.h }

// Capture returns the current screen as an RGBA image.
func (c *CGCapturer) Capture() (*image.RGBA, error) {
	cgImage := cgDisplayCreateImage(c.displayID)
	if cgImage == 0 {
		return nil, fmt.Errorf("CGDisplayCreateImage returned nil (screen recording permission?)")
	}
	defer cgImageRelease(cgImage)

	w := int(cgImageGetWidth(cgImage))
	h := int(cgImageGetHeight(cgImage))
	bytesPerRow := int(cgImageGetBytesPerRow(cgImage))
	bpp := int(cgImageGetBitsPerPixel(cgImage))

	provider := cgImageGetDataProvider(cgImage)
	if provider == 0 {
		return nil, fmt.Errorf("CGImageGetDataProvider returned nil")
	}

	cfData := cgDataProviderCopyData(provider)
	if cfData == 0 {
		return nil, fmt.Errorf("CGDataProviderCopyData returned nil")
	}
	defer cfRelease(cfData)

	dataLen := int(cfDataGetLength(cfData))
	dataPtr := cfDataGetBytePtr(cfData)
	if dataPtr == 0 || dataLen == 0 {
		return nil, fmt.Errorf("empty image data")
	}

	src := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), dataLen)
	img := image.NewRGBA(image.Rect(0, 0, w, h))

	bytesPerPixel := bpp / 8
	for row := 0; row < h; row++ {
		srcOff := row * bytesPerRow
		dstOff := row * img.Stride
		for col := 0; col < w; col++ {
			si := srcOff + col*bytesPerPixel
			di := dstOff + col*4
			img.Pix[di+0] = src[si+2] // R (from BGRA)
			img.Pix[di+1] = src[si+1] // G
			img.Pix[di+2] = src[si+0] // B
			img.Pix[di+3] = 0xff
		}
	}

	return img, nil
}

// MacPoller wraps CGCapturer in a continuous capture loop.
type MacPoller struct {
	mu    sync.Mutex
	frame *image.RGBA
	w, h  int
	done  chan struct{}
}

// NewMacPoller creates a capturer that continuously grabs the macOS display.
func NewMacPoller() *MacPoller {
	p := &MacPoller{done: make(chan struct{})}
	go p.loop()
	return p
}

// Close stops the capture loop.
func (p *MacPoller) Close() {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

// Width returns the screen width.
func (p *MacPoller) Width() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.w
}

// Height returns the screen height.
func (p *MacPoller) Height() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.h
}

// Capture returns the most recent frame.
func (p *MacPoller) Capture() (*image.RGBA, error) {
	p.mu.Lock()
	img := p.frame
	p.mu.Unlock()
	if img != nil {
		return img, nil
	}
	return nil, fmt.Errorf("no frame available yet")
}

func (p *MacPoller) loop() {
	var capturer *CGCapturer
	var initFails int

	for {
		select {
		case <-p.done:
			return
		default:
		}

		if capturer == nil {
			var err error
			capturer, err = NewCGCapturer()
			if err != nil {
				initFails++
				if initFails <= maxCapturerRetries {
					log.Debugf("macOS capturer: %v (attempt %d/%d)", err, initFails, maxCapturerRetries)
					select {
					case <-p.done:
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}
				log.Warnf("macOS capturer unavailable after %d attempts, stopping poller", maxCapturerRetries)
				return
			}
			initFails = 0
			p.mu.Lock()
			p.w, p.h = capturer.Width(), capturer.Height()
			p.mu.Unlock()
		}

		img, err := capturer.Capture()
		if err != nil {
			log.Debugf("macOS capture: %v", err)
			capturer = nil
			select {
			case <-p.done:
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}

		p.mu.Lock()
		p.frame = img
		p.mu.Unlock()

		select {
		case <-p.done:
			return
		case <-time.After(33 * time.Millisecond): // ~30 fps
		}
	}
}

var _ ScreenCapturer = (*MacPoller)(nil)
