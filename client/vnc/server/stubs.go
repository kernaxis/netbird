package server

import (
	"fmt"
	"image"
)

const maxCapturerRetries = 5

// StubCapturer is a placeholder for platforms without screen capture support.
type StubCapturer struct{}

// Width returns 0 on unsupported platforms.
func (c *StubCapturer) Width() int { return 0 }

// Height returns 0 on unsupported platforms.
func (c *StubCapturer) Height() int { return 0 }

// Capture returns an error on unsupported platforms.
func (c *StubCapturer) Capture() (*image.RGBA, error) {
	return nil, fmt.Errorf("screen capture not supported on this platform")
}

// StubInputInjector is a placeholder for platforms without input injection support.
type StubInputInjector struct{}

// InjectKey is a no-op on unsupported platforms.
func (s *StubInputInjector) InjectKey(_ uint32, _ bool) {}

// InjectPointer is a no-op on unsupported platforms.
func (s *StubInputInjector) InjectPointer(_ uint8, _, _, _, _ int) {}

// SetClipboard is a no-op on unsupported platforms.
func (s *StubInputInjector) SetClipboard(_ string) {}

// GetClipboard returns empty on unsupported platforms.
func (s *StubInputInjector) GetClipboard() string { return "" }
