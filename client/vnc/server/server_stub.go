//go:build !windows && !darwin && !freebsd && !(linux && !android)

package server

func (s *Server) platformInit() {}

// serviceAcceptLoop is not supported on non-Windows platforms.
func (s *Server) serviceAcceptLoop() {
	s.log.Warn("service mode not supported on this platform, falling back to direct mode")
	s.acceptLoop()
}

func (s *Server) platformSessionManager() virtualSessionManager {
	return nil
}
