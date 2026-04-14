//go:build windows

package server

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	sasDLL      = windows.NewLazySystemDLL("sas.dll")
	procSendSAS = sasDLL.NewProc("SendSAS")

	procConvertStringSecurityDescriptorToSecurityDescriptor = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
)

// sasSecurityAttributes builds a SECURITY_ATTRIBUTES that grants
// EVENT_MODIFY_STATE only to the SYSTEM account, preventing unprivileged
// local processes from triggering the Secure Attention Sequence.
func sasSecurityAttributes() (*windows.SecurityAttributes, error) {
	// SDDL: grant full access to SYSTEM (creates/waits) and EVENT_MODIFY_STATE
	// to the interactive user (IU) so the VNC agent in the console session can
	// signal it. Other local users and network users are denied.
	sddl, err := windows.UTF16PtrFromString("D:(A;;GA;;;SY)(A;;0x0002;;;IU)")
	if err != nil {
		return nil, err
	}
	var sd uintptr
	r, _, lerr := procConvertStringSecurityDescriptorToSecurityDescriptor.Call(
		uintptr(unsafe.Pointer(sddl)),
		1, // SDDL_REVISION_1
		uintptr(unsafe.Pointer(&sd)),
		0,
	)
	if r == 0 {
		return nil, lerr
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(sd)),
		InheritHandle:      0,
	}, nil
}

// enableSoftwareSAS sets the SoftwareSASGeneration registry key to allow
// services to trigger the Secure Attention Sequence via SendSAS. Without this,
// SendSAS silently does nothing on most Windows editions.
func enableSoftwareSAS() {
	key, _, err := registry.CreateKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		registry.SET_VALUE,
	)
	if err != nil {
		log.Warnf("open SoftwareSASGeneration registry key: %v", err)
		return
	}
	defer key.Close()

	if err := key.SetDWordValue("SoftwareSASGeneration", 1); err != nil {
		log.Warnf("set SoftwareSASGeneration: %v", err)
		return
	}
	log.Debug("SoftwareSASGeneration registry key set to 1 (services allowed)")
}

// startSASListener creates a named event with a restricted DACL and waits for
// the VNC input injector to signal it. When signaled, it calls SendSAS(FALSE)
// from Session 0 to trigger the Secure Attention Sequence (Ctrl+Alt+Del).
// Only SYSTEM processes can open the event.
func startSASListener() {
	enableSoftwareSAS()
	namePtr, err := windows.UTF16PtrFromString(sasEventName)
	if err != nil {
		log.Warnf("SAS listener UTF16: %v", err)
		return
	}
	sa, err := sasSecurityAttributes()
	if err != nil {
		log.Warnf("build SAS security descriptor: %v", err)
		return
	}
	ev, err := windows.CreateEvent(sa, 0, 0, namePtr)
	if err != nil {
		log.Warnf("SAS CreateEvent: %v", err)
		return
	}
	log.Info("SAS listener ready (Session 0)")
	go func() {
		defer windows.CloseHandle(ev)
		for {
			ret, _ := windows.WaitForSingleObject(ev, windows.INFINITE)
			if ret == windows.WAIT_OBJECT_0 {
				r, _, sasErr := procSendSAS.Call(0) // FALSE = not from service desktop
				if r == 0 {
					log.Warnf("SendSAS: %v", sasErr)
				} else {
					log.Info("SendSAS called from Session 0")
				}
			}
		}
	}()
}

// enablePrivilege enables a named privilege on the current process token.
func enablePrivilege(name string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	namePtr, _ := windows.UTF16PtrFromString(name)
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

func (s *Server) platformSessionManager() virtualSessionManager {
	return nil
}

// platformInit starts the SAS listener and enables privileges needed for
// Session 0 operations (agent spawning, SendSAS).
func (s *Server) platformInit() {
	for _, priv := range []string{"SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege"} {
		if err := enablePrivilege(priv); err != nil {
			log.Debugf("enable %s: %v", priv, err)
		}
	}
	startSASListener()
}

// serviceAcceptLoop runs in Session 0. It validates source IP and
// authenticates via JWT before proxying connections to the user-session agent.
func (s *Server) serviceAcceptLoop() {

	sm := newSessionManager(agentPort)
	go sm.run()

	log.Infof("service mode, proxying connections to agent on 127.0.0.1:%s", agentPort)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				sm.Stop()
				return
			default:
			}
			s.log.Debugf("accept VNC connection: %v", err)
			continue
		}

		go s.handleServiceConnection(conn, sm)
	}
}

// handleServiceConnection validates the source IP and JWT, then proxies
// the connection (with header bytes replayed) to the agent.
func (s *Server) handleServiceConnection(conn net.Conn, sm *sessionManager) {
	connLog := s.log.WithField("remote", conn.RemoteAddr().String())

	if !s.isAllowedSource(conn.RemoteAddr()) {
		conn.Close()
		return
	}

	var headerBuf bytes.Buffer
	tee := io.TeeReader(conn, &headerBuf)
	teeConn := &prefixConn{Reader: tee, Conn: conn}

	header, err := readConnectionHeader(teeConn)
	if err != nil {
		connLog.Debugf("read connection header: %v", err)
		conn.Close()
		return
	}

	if !s.disableAuth {
		if s.jwtConfig == nil {
			rejectConnection(conn, "auth enabled but no identity provider configured")
			connLog.Warn("auth rejected: no identity provider configured")
			return
		}
		if _, err := s.authenticateJWT(header); err != nil {
			rejectConnection(conn, fmt.Sprintf("auth: %v", err))
			connLog.Warnf("auth rejected: %v", err)
			return
		}
	}

	// Replay buffered header bytes + remaining stream to the agent.
	replayConn := &prefixConn{
		Reader: io.MultiReader(&headerBuf, conn),
		Conn:   conn,
	}
	proxyToAgent(replayConn, agentPort, sm.AuthToken())
}

// prefixConn wraps a net.Conn, overriding Read to use a different reader.
type prefixConn struct {
	io.Reader
	net.Conn
}

func (p *prefixConn) Read(b []byte) (int, error) {
	return p.Reader.Read(b)
}
