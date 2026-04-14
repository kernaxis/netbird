//go:build windows

package server

import "unsafe"

// swizzleBGRAtoRGBA swaps B and R channels in a BGRA pixel buffer in-place.
// Operates on uint32 words for throughput: one read-modify-write per pixel.
func swizzleBGRAtoRGBA(pix []byte) {
	n := len(pix) / 4
	pixels := unsafe.Slice((*uint32)(unsafe.Pointer(&pix[0])), n)
	for i := range n {
		p := pixels[i]
		// p = 0xAABBGGRR (little-endian BGRA in memory: B,G,R,A bytes)
		// We want 0xAABBGGRR -> 0xAARRGGBB (RGBA in memory: R,G,B,A bytes)
		// Swap byte 0 (B) and byte 2 (R), keep byte 1 (G) and byte 3 (A).
		pixels[i] = (p & 0xFF00FF00) | ((p & 0x00FF0000) >> 16) | ((p & 0x000000FF) << 16)
	}
}
