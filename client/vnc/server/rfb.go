package server

import (
	"bytes"
	"compress/zlib"
	"crypto/des"
	"encoding/binary"
	"image"
)

const (
	rfbProtocolVersion = "RFB 003.008\n"

	secNone    = 1
	secVNCAuth = 2

	// Client message types.
	clientSetPixelFormat           = 0
	clientSetEncodings             = 2
	clientFramebufferUpdateRequest = 3
	clientKeyEvent                 = 4
	clientPointerEvent             = 5
	clientCutText                  = 6

	// Server message types.
	serverFramebufferUpdate = 0
	serverCutText           = 3

	// Encoding types.
	encRaw  = 0
	encZlib = 6
)

// serverPixelFormat is the default pixel format advertised by the server:
// 32bpp RGBA, big-endian, true-colour, 8 bits per channel.
var serverPixelFormat = [16]byte{
	32,      // bits-per-pixel
	24,      // depth
	1,       // big-endian-flag
	1,       // true-colour-flag
	0, 255,  // red-max
	0, 255,  // green-max
	0, 255,  // blue-max
	16,      // red-shift
	8,       // green-shift
	0,       // blue-shift
	0, 0, 0, // padding
}

// clientPixelFormat holds the negotiated pixel format from the client.
type clientPixelFormat struct {
	bpp       uint8
	bigEndian uint8
	rMax      uint16
	gMax      uint16
	bMax      uint16
	rShift    uint8
	gShift    uint8
	bShift    uint8
}

func defaultClientPixelFormat() clientPixelFormat {
	return clientPixelFormat{
		bpp:       serverPixelFormat[0],
		bigEndian: serverPixelFormat[2],
		rMax:      binary.BigEndian.Uint16(serverPixelFormat[4:6]),
		gMax:      binary.BigEndian.Uint16(serverPixelFormat[6:8]),
		bMax:      binary.BigEndian.Uint16(serverPixelFormat[8:10]),
		rShift:    serverPixelFormat[10],
		gShift:    serverPixelFormat[11],
		bShift:    serverPixelFormat[12],
	}
}

func parsePixelFormat(pf []byte) clientPixelFormat {
	return clientPixelFormat{
		bpp:       pf[0],
		bigEndian: pf[2],
		rMax:      binary.BigEndian.Uint16(pf[4:6]),
		gMax:      binary.BigEndian.Uint16(pf[6:8]),
		bMax:      binary.BigEndian.Uint16(pf[8:10]),
		rShift:    pf[10],
		gShift:    pf[11],
		bShift:    pf[12],
	}
}

// encodeRawRect encodes a framebuffer region as a raw RFB rectangle.
// The returned buffer includes the FramebufferUpdate header (1 rectangle).
func encodeRawRect(img *image.RGBA, pf clientPixelFormat, x, y, w, h int) []byte {
	bytesPerPixel := max(int(pf.bpp)/8, 1)

	pixelBytes := w * h * bytesPerPixel
	buf := make([]byte, 4+12+pixelBytes)

	// FramebufferUpdate header.
	buf[0] = serverFramebufferUpdate
	buf[1] = 0 // padding
	binary.BigEndian.PutUint16(buf[2:4], 1)

	// Rectangle header.
	binary.BigEndian.PutUint16(buf[4:6], uint16(x))
	binary.BigEndian.PutUint16(buf[6:8], uint16(y))
	binary.BigEndian.PutUint16(buf[8:10], uint16(w))
	binary.BigEndian.PutUint16(buf[10:12], uint16(h))
	binary.BigEndian.PutUint32(buf[12:16], uint32(encRaw))

	off := 16
	stride := img.Stride
	for row := y; row < y+h; row++ {
		for col := x; col < x+w; col++ {
			p := row*stride + col*4
			r, g, b := img.Pix[p], img.Pix[p+1], img.Pix[p+2]

			rv := uint32(r) * uint32(pf.rMax) / 255
			gv := uint32(g) * uint32(pf.gMax) / 255
			bv := uint32(b) * uint32(pf.bMax) / 255
			pixel := (rv << pf.rShift) | (gv << pf.gShift) | (bv << pf.bShift)

			if pf.bigEndian != 0 {
				for i := range bytesPerPixel {
					buf[off+i] = byte(pixel >> uint((bytesPerPixel-1-i)*8))
				}
			} else {
				for i := range bytesPerPixel {
					buf[off+i] = byte(pixel >> uint(i*8))
				}
			}
			off += bytesPerPixel
		}
	}

	return buf
}

// vncAuthEncrypt encrypts a 16-byte challenge using the VNC DES scheme.
func vncAuthEncrypt(challenge []byte, password string) []byte {
	key := make([]byte, 8)
	for i, c := range []byte(password) {
		if i >= 8 {
			break
		}
		key[i] = reverseBits(c)
	}
	block, _ := des.NewCipher(key)
	out := make([]byte, 16)
	block.Encrypt(out[:8], challenge[:8])
	block.Encrypt(out[8:], challenge[8:])
	return out
}

func reverseBits(b byte) byte {
	var r byte
	for range 8 {
		r = (r << 1) | (b & 1)
		b >>= 1
	}
	return r
}

// encodeZlibRect encodes a framebuffer region using Zlib compression.
// The zlib stream is continuous for the entire VNC session: noVNC creates
// one inflate context at startup and reuses it for all zlib-encoded rects.
// We must NOT reset the zlib writer between calls.
func encodeZlibRect(img *image.RGBA, pf clientPixelFormat, x, y, w, h int, zw *zlib.Writer, zbuf *bytes.Buffer) []byte {
	bytesPerPixel := max(int(pf.bpp)/8, 1)

	// Clear the output buffer but keep the deflate dictionary intact.
	zbuf.Reset()

	stride := img.Stride
	pixel := make([]byte, bytesPerPixel)
	for row := y; row < y+h; row++ {
		for col := x; col < x+w; col++ {
			p := row*stride + col*4
			r, g, b := img.Pix[p], img.Pix[p+1], img.Pix[p+2]

			rv := uint32(r) * uint32(pf.rMax) / 255
			gv := uint32(g) * uint32(pf.gMax) / 255
			bv := uint32(b) * uint32(pf.bMax) / 255
			val := (rv << pf.rShift) | (gv << pf.gShift) | (bv << pf.bShift)

			if pf.bigEndian != 0 {
				for i := range bytesPerPixel {
					pixel[i] = byte(val >> uint((bytesPerPixel-1-i)*8))
				}
			} else {
				for i := range bytesPerPixel {
					pixel[i] = byte(val >> uint(i*8))
				}
			}
			zw.Write(pixel)
		}
	}
	zw.Flush()

	compressed := zbuf.Bytes()

	// Build the FramebufferUpdate message.
	buf := make([]byte, 4+12+4+len(compressed))
	buf[0] = serverFramebufferUpdate
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], 1) // 1 rectangle

	binary.BigEndian.PutUint16(buf[4:6], uint16(x))
	binary.BigEndian.PutUint16(buf[6:8], uint16(y))
	binary.BigEndian.PutUint16(buf[8:10], uint16(w))
	binary.BigEndian.PutUint16(buf[10:12], uint16(h))
	binary.BigEndian.PutUint32(buf[12:16], uint32(encZlib))
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(compressed)))
	copy(buf[20:], compressed)

	return buf
}

// diffRects compares two RGBA images and returns a list of dirty rectangles.
// Divides the screen into tiles and checks each for changes.
func diffRects(prev, cur *image.RGBA, w, h, tileSize int) [][4]int {
	if prev == nil {
		return [][4]int{{0, 0, w, h}}
	}

	var rects [][4]int
	for ty := 0; ty < h; ty += tileSize {
		th := min(tileSize, h-ty)
		for tx := 0; tx < w; tx += tileSize {
			tw := min(tileSize, w-tx)
			if tileChanged(prev, cur, tx, ty, tw, th) {
				rects = append(rects, [4]int{tx, ty, tw, th})
			}
		}
	}
	return rects
}

func tileChanged(prev, cur *image.RGBA, x, y, w, h int) bool {
	stride := prev.Stride
	for row := y; row < y+h; row++ {
		off := row*stride + x*4
		end := off + w*4
		prevRow := prev.Pix[off:end]
		curRow := cur.Pix[off:end]
		if !bytes.Equal(prevRow, curRow) {
			return true
		}
	}
	return false
}

// zlibState holds the persistent zlib writer and buffer for a session.
type zlibState struct {
	buf *bytes.Buffer
	w   *zlib.Writer
}

func newZlibState() *zlibState {
	buf := &bytes.Buffer{}
	w, _ := zlib.NewWriterLevel(buf, zlib.BestSpeed)
	return &zlibState{buf: buf, w: w}
}

func (z *zlibState) Close() error {
	return z.w.Close()
}
