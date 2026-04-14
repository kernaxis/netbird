//go:build darwin && !ios

package server

func (s *Server) platformInit() {}

// serviceAcceptLoop is not supported on macOS.
func (s *Server) serviceAcceptLoop() {
	s.log.Warn("service mode not supported on macOS, falling back to direct mode")
	s.acceptLoop()
}

func (s *Server) platformSessionManager() virtualSessionManager {
	return nil
}
