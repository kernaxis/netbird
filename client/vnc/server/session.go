package server

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"image"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	readDeadline    = 60 * time.Second
	maxCutTextBytes = 1 << 20 // 1 MiB
)

const tileSize = 64 // pixels per tile for dirty-rect detection

type session struct {
	conn     net.Conn
	capturer ScreenCapturer
	injector InputInjector
	serverW  int
	serverH  int
	password string
	log      *log.Entry

	writeMu    sync.Mutex
	pf         clientPixelFormat
	useZlib    bool
	zlib       *zlibState
	prevFrame  *image.RGBA
	idleFrames int
}

func (s *session) addr() string { return s.conn.RemoteAddr().String() }

// serve runs the full RFB session lifecycle.
func (s *session) serve() {
	defer s.conn.Close()
	s.pf = defaultClientPixelFormat()

	if err := s.handshake(); err != nil {
		s.log.Warnf("handshake with %s: %v", s.addr(), err)
		return
	}
	s.log.Infof("client connected: %s", s.addr())

	done := make(chan struct{})
	defer close(done)
	go s.clipboardPoll(done)

	if err := s.messageLoop(); err != nil && err != io.EOF {
		s.log.Warnf("client %s disconnected: %v", s.addr(), err)
	} else {
		s.log.Infof("client disconnected: %s", s.addr())
	}
}

// clipboardPoll periodically checks the server-side clipboard and sends
// changes to the VNC client. Only runs during active sessions.
func (s *session) clipboardPoll(done <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastClip string
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			text := s.injector.GetClipboard()
			if len(text) > maxCutTextBytes {
				text = text[:maxCutTextBytes]
			}
			if text != "" && text != lastClip {
				lastClip = text
				if err := s.sendServerCutText(text); err != nil {
					s.log.Debugf("send clipboard to client: %v", err)
					return
				}
			}
		}
	}
}

func (s *session) handshake() error {
	// Send protocol version.
	if _, err := io.WriteString(s.conn, rfbProtocolVersion); err != nil {
		return fmt.Errorf("send version: %w", err)
	}

	// Read client version.
	var clientVer [12]byte
	if _, err := io.ReadFull(s.conn, clientVer[:]); err != nil {
		return fmt.Errorf("read client version: %w", err)
	}

	// Send supported security types.
	if err := s.sendSecurityTypes(); err != nil {
		return err
	}

	// Read chosen security type.
	var secType [1]byte
	if _, err := io.ReadFull(s.conn, secType[:]); err != nil {
		return fmt.Errorf("read security type: %w", err)
	}

	if err := s.handleSecurity(secType[0]); err != nil {
		return err
	}

	// Read ClientInit.
	var clientInit [1]byte
	if _, err := io.ReadFull(s.conn, clientInit[:]); err != nil {
		return fmt.Errorf("read ClientInit: %w", err)
	}

	return s.sendServerInit()
}

func (s *session) sendSecurityTypes() error {
	if s.password == "" {
		_, err := s.conn.Write([]byte{1, secNone})
		return err
	}
	_, err := s.conn.Write([]byte{1, secVNCAuth})
	return err
}

func (s *session) handleSecurity(secType byte) error {
	switch secType {
	case secVNCAuth:
		return s.doVNCAuth()
	case secNone:
		return binary.Write(s.conn, binary.BigEndian, uint32(0))
	default:
		return fmt.Errorf("unsupported security type: %d", secType)
	}
}

func (s *session) doVNCAuth() error {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("generate challenge: %w", err)
	}
	if _, err := s.conn.Write(challenge); err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}

	response := make([]byte, 16)
	if _, err := io.ReadFull(s.conn, response); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	var result uint32
	if s.password != "" {
		expected := vncAuthEncrypt(challenge, s.password)
		if !bytes.Equal(expected, response) {
			result = 1
		}
	}

	if err := binary.Write(s.conn, binary.BigEndian, result); err != nil {
		return fmt.Errorf("send auth result: %w", err)
	}
	if result != 0 {
		msg := "authentication failed"
		_ = binary.Write(s.conn, binary.BigEndian, uint32(len(msg)))
		_, _ = s.conn.Write([]byte(msg))
		return fmt.Errorf("authentication failed from %s", s.addr())
	}
	return nil
}

func (s *session) sendServerInit() error {
	name := []byte("NetBird VNC")
	buf := make([]byte, 0, 4+16+4+len(name))

	// Framebuffer width and height.
	buf = append(buf, byte(s.serverW>>8), byte(s.serverW))
	buf = append(buf, byte(s.serverH>>8), byte(s.serverH))

	// Server pixel format.
	buf = append(buf, serverPixelFormat[:]...)

	// Desktop name.
	buf = append(buf,
		byte(len(name)>>24), byte(len(name)>>16),
		byte(len(name)>>8), byte(len(name)),
	)
	buf = append(buf, name...)

	_, err := s.conn.Write(buf)
	return err
}

func (s *session) messageLoop() error {
	for {
		var msgType [1]byte
		if err := s.conn.SetDeadline(time.Now().Add(readDeadline)); err != nil {
			return fmt.Errorf("set deadline: %w", err)
		}
		if _, err := io.ReadFull(s.conn, msgType[:]); err != nil {
			return err
		}
		_ = s.conn.SetDeadline(time.Time{})

		switch msgType[0] {
		case clientSetPixelFormat:
			if err := s.handleSetPixelFormat(); err != nil {
				return err
			}
		case clientSetEncodings:
			if err := s.handleSetEncodings(); err != nil {
				return err
			}
		case clientFramebufferUpdateRequest:
			if err := s.handleFBUpdateRequest(); err != nil {
				return err
			}
		case clientKeyEvent:
			if err := s.handleKeyEvent(); err != nil {
				return err
			}
		case clientPointerEvent:
			if err := s.handlePointerEvent(); err != nil {
				return err
			}
		case clientCutText:
			if err := s.handleCutText(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown client message type: %d", msgType[0])
		}
	}
}

func (s *session) handleSetPixelFormat() error {
	var buf [19]byte // 3 padding + 16 pixel format
	if _, err := io.ReadFull(s.conn, buf[:]); err != nil {
		return fmt.Errorf("read SetPixelFormat: %w", err)
	}
	s.pf = parsePixelFormat(buf[3:19])
	return nil
}

func (s *session) handleSetEncodings() error {
	var header [3]byte // 1 padding + 2 number-of-encodings
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return fmt.Errorf("read SetEncodings header: %w", err)
	}
	numEnc := binary.BigEndian.Uint16(header[1:3])
	buf := make([]byte, int(numEnc)*4)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return err
	}

	// Check if client supports zlib encoding.
	for i := range int(numEnc) {
		enc := int32(binary.BigEndian.Uint32(buf[i*4 : i*4+4]))
		if enc == encZlib {
			s.useZlib = true
			if s.zlib == nil {
				s.zlib = newZlibState()
			}
			s.log.Debugf("client supports zlib encoding")
			break
		}
	}
	return nil
}

func (s *session) handleFBUpdateRequest() error {
	var req [9]byte
	if _, err := io.ReadFull(s.conn, req[:]); err != nil {
		return fmt.Errorf("read FBUpdateRequest: %w", err)
	}
	incremental := req[0]

	img, err := s.capturer.Capture()
	if err != nil {
		return fmt.Errorf("capture screen: %w", err)
	}

	if incremental == 1 && s.prevFrame != nil {
		rects := diffRects(s.prevFrame, img, s.serverW, s.serverH, tileSize)
		if len(rects) == 0 {
			// Nothing changed. Back off briefly before responding to reduce
			// CPU usage when the screen is static. The client re-requests
			// immediately after receiving our empty response, so without
			// this delay we'd spin at ~1000fps checking for changes.
			s.idleFrames++
			delay := min(s.idleFrames*5, 100) // 5ms → 100ms adaptive backoff
			time.Sleep(time.Duration(delay) * time.Millisecond)
			s.savePrevFrame(img)
			return s.sendEmptyUpdate()
		}
		s.idleFrames = 0
		s.savePrevFrame(img)
		return s.sendDirtyRects(img, rects)
	}

	// Full update.
	s.idleFrames = 0
	s.savePrevFrame(img)
	return s.sendFullUpdate(img)
}

// savePrevFrame copies img's pixel data into prevFrame. This is necessary
// because some capturers (DXGI) reuse the same image buffer across calls,
// so a simple pointer assignment would make prevFrame alias the live buffer
// and diffRects would always see zero changes.
func (s *session) savePrevFrame(img *image.RGBA) {
	if s.prevFrame == nil || s.prevFrame.Rect != img.Rect {
		s.prevFrame = image.NewRGBA(img.Rect)
	}
	copy(s.prevFrame.Pix, img.Pix)
}

// sendEmptyUpdate sends a FramebufferUpdate with zero rectangles.
func (s *session) sendEmptyUpdate() error {
	var buf [4]byte
	buf[0] = serverFramebufferUpdate
	s.writeMu.Lock()
	_, err := s.conn.Write(buf[:])
	s.writeMu.Unlock()
	return err
}

func (s *session) sendFullUpdate(img *image.RGBA) error {
	w, h := s.serverW, s.serverH

	var buf []byte
	if s.useZlib && s.zlib != nil {
		buf = encodeZlibRect(img, s.pf, 0, 0, w, h, s.zlib.w, s.zlib.buf)
	} else {
		buf = encodeRawRect(img, s.pf, 0, 0, w, h)
	}

	s.writeMu.Lock()
	_, err := s.conn.Write(buf)
	s.writeMu.Unlock()
	return err
}

func (s *session) sendDirtyRects(img *image.RGBA, rects [][4]int) error {
	// Build a multi-rectangle FramebufferUpdate.
	// Header: type(1) + padding(1) + numRects(2)
	header := make([]byte, 4)
	header[0] = serverFramebufferUpdate
	binary.BigEndian.PutUint16(header[2:4], uint16(len(rects)))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.conn.Write(header); err != nil {
		return err
	}

	for _, r := range rects {
		x, y, w, h := r[0], r[1], r[2], r[3]

		var rectBuf []byte
		if s.useZlib && s.zlib != nil {
			rectBuf = encodeZlibRect(img, s.pf, x, y, w, h, s.zlib.w, s.zlib.buf)
			// encodeZlibRect includes its own FBUpdate header for 1 rect.
			// For multi-rect, we need just the rect data without the FBUpdate header.
			// Skip the 4-byte FBUpdate header since we already sent ours.
			rectBuf = rectBuf[4:]
		} else {
			rectBuf = encodeRawRect(img, s.pf, x, y, w, h)
			rectBuf = rectBuf[4:] // skip FBUpdate header
		}

		if _, err := s.conn.Write(rectBuf); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) handleKeyEvent() error {
	var data [7]byte
	if _, err := io.ReadFull(s.conn, data[:]); err != nil {
		return fmt.Errorf("read KeyEvent: %w", err)
	}
	down := data[0] == 1
	keysym := binary.BigEndian.Uint32(data[3:7])
	s.injector.InjectKey(keysym, down)
	return nil
}

func (s *session) handlePointerEvent() error {
	var data [5]byte
	if _, err := io.ReadFull(s.conn, data[:]); err != nil {
		return fmt.Errorf("read PointerEvent: %w", err)
	}
	buttonMask := data[0]
	x := int(binary.BigEndian.Uint16(data[1:3]))
	y := int(binary.BigEndian.Uint16(data[3:5]))
	s.injector.InjectPointer(buttonMask, x, y, s.serverW, s.serverH)
	return nil
}

func (s *session) handleCutText() error {
	var header [7]byte // 3 padding + 4 length
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return fmt.Errorf("read CutText header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[3:7])
	if length > maxCutTextBytes {
		return fmt.Errorf("cut text too large: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return fmt.Errorf("read CutText payload: %w", err)
	}
	s.injector.SetClipboard(string(buf))
	return nil
}

// sendServerCutText sends clipboard text from the server to the client.
func (s *session) sendServerCutText(text string) error {
	data := []byte(text)
	buf := make([]byte, 8+len(data))
	buf[0] = serverCutText
	// buf[1:4] = padding (zero)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(data)))
	copy(buf[8:], data)

	s.writeMu.Lock()
	_, err := s.conn.Write(buf)
	s.writeMu.Unlock()
	return err
}
