//go:build (linux && !android) || freebsd

package internal

import (
	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newPlatformVNC() (vncserver.ScreenCapturer, vncserver.InputInjector) {
	capturer := vncserver.NewX11Poller("")
	injector, err := vncserver.NewX11InputInjector("")
	if err != nil {
		log.Debugf("VNC: X11 input injector: %v", err)
		return capturer, &vncserver.StubInputInjector{}
	}
	return capturer, injector
}

func vncNeedsServiceMode() bool {
	return false
}
