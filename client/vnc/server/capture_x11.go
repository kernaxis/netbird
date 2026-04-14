//go:build (linux && !android) || freebsd

package server

import (
	"fmt"
	"image"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
)

// X11Capturer captures the screen from an X11 display using the MIT-SHM extension.
type X11Capturer struct {
	mu      sync.Mutex
	conn    *xgb.Conn
	screen  *xproto.ScreenInfo
	w, h    int
	shmID   int
	shmAddr []byte
	shmSeg  uint32 // shm.Seg
	useSHM  bool
}

// detectX11Display finds the active X11 display and sets DISPLAY/XAUTHORITY
// environment variables if needed. This is required when running as a system
// service where these vars aren't set.
func detectX11Display() {
	if os.Getenv("DISPLAY") != "" {
		return
	}

	// Try /proc first (Linux), then ps fallback (FreeBSD and others).
	if detectX11FromProc() {
		return
	}
	if detectX11FromSockets() {
		return
	}
}

// detectX11FromProc scans /proc/*/cmdline for Xorg (Linux).
func detectX11FromProc() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if display, auth := parseXorgArgs(splitCmdline(cmdline)); display != "" {
			setDisplayEnv(display, auth)
			return true
		}
	}
	return false
}

// detectX11FromSockets checks /tmp/.X11-unix/ for X sockets and uses ps
// to find the auth file. Works on FreeBSD and other systems without /proc.
func detectX11FromSockets() bool {
	entries, err := os.ReadDir("/tmp/.X11-unix")
	if err != nil {
		return false
	}

	// Find the lowest display number.
	for _, e := range entries {
		name := e.Name()
		if len(name) < 2 || name[0] != 'X' {
			continue
		}
		display := ":" + name[1:]
		os.Setenv("DISPLAY", display)
		log.Infof("auto-detected DISPLAY=%s (from socket)", display)

		// Try to find -auth from ps output.
		if auth := findXorgAuthFromPS(); auth != "" {
			os.Setenv("XAUTHORITY", auth)
			log.Infof("auto-detected XAUTHORITY=%s (from ps)", auth)
		}
		return true
	}
	return false
}

// findXorgAuthFromPS runs ps to find Xorg and extract its -auth argument.
func findXorgAuthFromPS() string {
	out, err := exec.Command("ps", "auxww").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "Xorg") && !strings.Contains(line, "/X ") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "-auth" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}

func parseXorgArgs(args []string) (display, auth string) {
	if len(args) == 0 {
		return "", ""
	}
	base := args[0]
	if !(base == "Xorg" || base == "X" || len(base) > 0 && base[len(base)-1] == 'X' ||
		strings.Contains(base, "/Xorg") || strings.Contains(base, "/X")) {
		return "", ""
	}
	for i, arg := range args[1:] {
		if len(arg) > 0 && arg[0] == ':' {
			display = arg
		}
		if arg == "-auth" && i+2 < len(args) {
			auth = args[i+2]
		}
	}
	return display, auth
}

func setDisplayEnv(display, auth string) {
	os.Setenv("DISPLAY", display)
	log.Infof("auto-detected DISPLAY=%s", display)
	if auth != "" {
		os.Setenv("XAUTHORITY", auth)
		log.Infof("auto-detected XAUTHORITY=%s", auth)
	}
}

func splitCmdline(data []byte) []string {
	var args []string
	for _, b := range splitNull(data) {
		if len(b) > 0 {
			args = append(args, string(b))
		}
	}
	return args
}

func splitNull(data []byte) [][]byte {
	var parts [][]byte
	start := 0
	for i, b := range data {
		if b == 0 {
			parts = append(parts, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		parts = append(parts, data[start:])
	}
	return parts
}

// NewX11Capturer connects to the X11 display and sets up shared memory capture.
func NewX11Capturer(display string) (*X11Capturer, error) {
	detectX11Display()

	if display == "" {
		display = os.Getenv("DISPLAY")
	}
	if display == "" {
		return nil, fmt.Errorf("DISPLAY not set and no Xorg process found")
	}

	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		return nil, fmt.Errorf("connect to X11 display %s: %w", display, err)
	}

	setup := xproto.Setup(conn)
	if len(setup.Roots) == 0 {
		conn.Close()
		return nil, fmt.Errorf("no X11 screens")
	}
	screen := setup.Roots[0]

	c := &X11Capturer{
		conn:   conn,
		screen: &screen,
		w:      int(screen.WidthInPixels),
		h:      int(screen.HeightInPixels),
	}

	if err := c.initSHM(); err != nil {
		log.Debugf("X11 SHM not available, using slow GetImage: %v", err)
	}

	log.Infof("X11 capturer ready: %dx%d (display=%s, shm=%v)", c.w, c.h, display, c.useSHM)
	return c, nil
}

// initSHM is implemented in capture_x11_shm_linux.go (requires SysV SHM).
// On platforms without SysV SHM (FreeBSD), a stub returns an error and
// the capturer falls back to GetImage.

// Width returns the screen width.
func (c *X11Capturer) Width() int { return c.w }

// Height returns the screen height.
func (c *X11Capturer) Height() int { return c.h }

// Capture returns the current screen as an RGBA image.
func (c *X11Capturer) Capture() (*image.RGBA, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.useSHM {
		return c.captureSHM()
	}
	return c.captureGetImage()
}

// captureSHM is implemented in capture_x11_shm_linux.go.

func (c *X11Capturer) captureGetImage() (*image.RGBA, error) {
	cookie := xproto.GetImage(c.conn, xproto.ImageFormatZPixmap,
		xproto.Drawable(c.screen.Root),
		0, 0, uint16(c.w), uint16(c.h), 0xFFFFFFFF)

	reply, err := cookie.Reply()
	if err != nil {
		return nil, fmt.Errorf("GetImage: %w", err)
	}

	img := image.NewRGBA(image.Rect(0, 0, c.w, c.h))
	data := reply.Data
	n := c.w * c.h * 4
	if len(data) < n {
		return nil, fmt.Errorf("GetImage returned %d bytes, expected %d", len(data), n)
	}

	for i := 0; i < n; i += 4 {
		img.Pix[i+0] = data[i+2] // R
		img.Pix[i+1] = data[i+1] // G
		img.Pix[i+2] = data[i+0] // B
		img.Pix[i+3] = 0xff
	}
	return img, nil
}

// Close releases X11 resources.
func (c *X11Capturer) Close() {
	c.closeSHM()
	c.conn.Close()
}

// closeSHM is implemented in capture_x11_shm_linux.go.

// X11Poller wraps X11Capturer in a continuous capture loop, matching the
// DesktopCapturer pattern from Windows.
type X11Poller struct {
	mu      sync.Mutex
	frame   *image.RGBA
	w, h    int
	display string
	done    chan struct{}
}

// NewX11Poller creates a capturer that continuously grabs the X11 display.
func NewX11Poller(display string) *X11Poller {
	p := &X11Poller{
		display: display,
		done:    make(chan struct{}),
	}
	go p.loop()
	return p
}

// Close stops the capture loop.
func (p *X11Poller) Close() {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

// Width returns the screen width.
func (p *X11Poller) Width() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.w
}

// Height returns the screen height.
func (p *X11Poller) Height() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.h
}

// Capture returns the most recent frame.
func (p *X11Poller) Capture() (*image.RGBA, error) {
	p.mu.Lock()
	img := p.frame
	p.mu.Unlock()
	if img != nil {
		return img, nil
	}
	return nil, fmt.Errorf("no frame available yet")
}

func (p *X11Poller) loop() {
	var capturer *X11Capturer
	var initFails int

	defer func() {
		if capturer != nil {
			capturer.Close()
		}
	}()

	for {
		select {
		case <-p.done:
			return
		default:
		}

		if capturer == nil {
			var err error
			capturer, err = NewX11Capturer(p.display)
			if err != nil {
				initFails++
				if initFails <= maxCapturerRetries {
					log.Debugf("X11 capturer: %v (attempt %d/%d)", err, initFails, maxCapturerRetries)
					select {
					case <-p.done:
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}
				log.Warnf("X11 capturer unavailable after %d attempts, stopping poller", maxCapturerRetries)
				return
			}
			initFails = 0
			p.mu.Lock()
			p.w, p.h = capturer.Width(), capturer.Height()
			p.mu.Unlock()
		}

		img, err := capturer.Capture()
		if err != nil {
			log.Debugf("X11 capture: %v", err)
			capturer.Close()
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
