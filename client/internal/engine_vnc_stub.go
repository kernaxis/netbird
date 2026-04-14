//go:build !windows && !darwin && !freebsd && !(linux && !android)

package internal

import vncserver "github.com/netbirdio/netbird/client/vnc/server"

func newPlatformVNC() (vncserver.ScreenCapturer, vncserver.InputInjector) {
	return nil, nil
}

func vncNeedsServiceMode() bool {
	return false
}
