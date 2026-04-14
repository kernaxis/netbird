//go:build windows

package server

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	agentPort = "15900"

	// agentTokenLen is the length of the random authentication token
	// used to verify that connections to the agent come from the service.
	agentTokenLen = 32

	stillActive = 259

	tokenPrimary          = 1
	securityImpersonation = 2
	tokenSessionID        = 12

	createUnicodeEnvironment = 0x00000400
	createNoWindow           = 0x08000000
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	userenv  = windows.NewLazySystemDLL("userenv.dll")

	procWTSGetActiveConsoleSessionId = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procSetTokenInformation          = advapi32.NewProc("SetTokenInformation")
	procCreateEnvironmentBlock       = userenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock      = userenv.NewProc("DestroyEnvironmentBlock")

	wtsapi32                  = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateSessionsW = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory         = wtsapi32.NewProc("WTSFreeMemory")
)

// GetCurrentSessionID returns the session ID of the current process.
func GetCurrentSessionID() uint32 {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY, &token); err != nil {
		return 0
	}
	defer token.Close()
	var id uint32
	var ret uint32
	_ = windows.GetTokenInformation(token, windows.TokenSessionId,
		(*byte)(unsafe.Pointer(&id)), 4, &ret)
	return id
}

func getConsoleSessionID() uint32 {
	r, _, _ := procWTSGetActiveConsoleSessionId.Call()
	return uint32(r)
}

const (
	wtsActive       = 0
	wtsConnected    = 1
	wtsDisconnected = 4
)

type wtsSessionInfo struct {
	SessionID      uint32
	WinStationName [66]byte // actually *uint16, but we just need the struct size
	State          uint32
}

// getActiveSessionID returns the session ID of the best session to attach to.
// Prefers an active (logged-in, interactive) session over the console session.
// This avoids kicking out an RDP user when the console is at the login screen.
func getActiveSessionID() uint32 {
	var sessionInfo uintptr
	var count uint32

	r, _, _ := procWTSEnumerateSessionsW.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		0, // reserved
		1, // version
		uintptr(unsafe.Pointer(&sessionInfo)),
		uintptr(unsafe.Pointer(&count)),
	)
	if r == 0 || count == 0 {
		return getConsoleSessionID()
	}
	defer procWTSFreeMemory.Call(sessionInfo)

	type wtsSession struct {
		SessionID uint32
		Station   *uint16
		State     uint32
	}
	sessions := unsafe.Slice((*wtsSession)(unsafe.Pointer(sessionInfo)), count)

	// Find the first active session (not session 0, which is the services session).
	var bestID uint32
	found := false
	for _, s := range sessions {
		if s.SessionID == 0 {
			continue
		}
		if s.State == wtsActive {
			bestID = s.SessionID
			found = true
			break
		}
	}

	if !found {
		return getConsoleSessionID()
	}
	return bestID
}

// getSystemTokenForSession duplicates the current SYSTEM token and sets its
// session ID so the spawned process runs in the target session. Using a SYSTEM
// token gives access to both Default and Winlogon desktops plus UIPI bypass.
func getSystemTokenForSession(sessionID uint32) (windows.Token, error) {
	var cur windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.MAXIMUM_ALLOWED, &cur); err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer cur.Close()

	var dup windows.Token
	if err := windows.DuplicateTokenEx(cur, windows.MAXIMUM_ALLOWED, nil,
		securityImpersonation, tokenPrimary, &dup); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}

	sid := sessionID
	r, _, err := procSetTokenInformation.Call(
		uintptr(dup),
		uintptr(tokenSessionID),
		uintptr(unsafe.Pointer(&sid)),
		unsafe.Sizeof(sid),
	)
	if r == 0 {
		dup.Close()
		return 0, fmt.Errorf("SetTokenInformation(SessionId=%d): %w", sessionID, err)
	}
	return dup, nil
}

const agentTokenEnvVar = "NB_VNC_AGENT_TOKEN"

// injectEnvVar appends a KEY=VALUE entry to a Unicode environment block.
// The block is a sequence of null-terminated UTF-16 strings, terminated by
// an extra null. Returns a new block pointer with the entry added.
func injectEnvVar(envBlock uintptr, key, value string) uintptr {
	entry := key + "=" + value

	// Walk the existing block to find its total length.
	ptr := (*uint16)(unsafe.Pointer(envBlock))
	var totalChars int
	for {
		ch := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(totalChars)*2))
		if ch == 0 {
			// Check for double-null terminator.
			next := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(totalChars+1)*2))
			totalChars++
			if next == 0 {
				// End of block (don't count the final null yet, we'll rebuild).
				break
			}
		} else {
			totalChars++
		}
	}

	entryUTF16, _ := windows.UTF16FromString(entry)
	// New block: existing entries + new entry (null-terminated) + final null.
	newLen := totalChars + len(entryUTF16) + 1
	newBlock := make([]uint16, newLen)
	// Copy existing entries (up to but not including the final null).
	for i := range totalChars {
		newBlock[i] = *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)*2))
	}
	copy(newBlock[totalChars:], entryUTF16)
	newBlock[newLen-1] = 0 // final null terminator

	return uintptr(unsafe.Pointer(&newBlock[0]))
}

func spawnAgentInSession(sessionID uint32, port string, authToken string) (windows.Handle, error) {
	token, err := getSystemTokenForSession(sessionID)
	if err != nil {
		return 0, fmt.Errorf("get SYSTEM token for session %d: %w", sessionID, err)
	}
	defer token.Close()

	var envBlock uintptr
	r, _, _ := procCreateEnvironmentBlock.Call(
		uintptr(unsafe.Pointer(&envBlock)),
		uintptr(token),
		0,
	)
	if r != 0 {
		defer procDestroyEnvironmentBlock.Call(envBlock)
	}

	// Inject the auth token into the environment block so it doesn't appear
	// in the process command line (visible via tasklist/wmic).
	if r != 0 {
		envBlock = injectEnvVar(envBlock, agentTokenEnvVar, authToken)
	}

	exePath, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("get executable path: %w", err)
	}

	cmdLine := fmt.Sprintf(`"%s" vnc-agent --port %s`, exePath, port)
	cmdLineW, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return 0, fmt.Errorf("UTF16 cmdline: %w", err)
	}

	// Create an inheritable pipe for the agent's stderr so we can relog
	// its output in the service process.
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1

	var stderrRead, stderrWrite windows.Handle
	if err := windows.CreatePipe(&stderrRead, &stderrWrite, &sa, 0); err != nil {
		return 0, fmt.Errorf("create stderr pipe: %w", err)
	}
	// The read end must NOT be inherited by the child.
	windows.SetHandleInformation(stderrRead, windows.HANDLE_FLAG_INHERIT, 0)

	desktop, _ := windows.UTF16PtrFromString(`WinSta0\Default`)
	si := windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop:    desktop,
		Flags:      windows.STARTF_USESHOWWINDOW | windows.STARTF_USESTDHANDLES,
		ShowWindow: 0,
		StdErr:     stderrWrite,
		StdOutput:  stderrWrite,
	}
	var pi windows.ProcessInformation

	var envPtr *uint16
	if envBlock != 0 {
		envPtr = (*uint16)(unsafe.Pointer(envBlock))
	}

	err = windows.CreateProcessAsUser(
		token, nil, cmdLineW,
		nil, nil, true, // inheritHandles=true for the pipe
		createUnicodeEnvironment|createNoWindow,
		envPtr, nil, &si, &pi,
	)
	// Close the write end in the parent so reads will get EOF when the child exits.
	windows.CloseHandle(stderrWrite)
	if err != nil {
		windows.CloseHandle(stderrRead)
		return 0, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)

	// Relog agent output in the service with a [vnc-agent] prefix.
	go relogAgentOutput(stderrRead)

	log.Infof("spawned agent PID=%d in session %d on port %s", pi.ProcessId, sessionID, port)
	return pi.Process, nil
}

// sessionManager monitors the active console session and ensures a VNC agent
// process is running in it. When the session changes (e.g., user switch, RDP
// connect/disconnect), it kills the old agent and spawns a new one.
type sessionManager struct {
	port      string
	mu        sync.Mutex
	agentProc windows.Handle
	sessionID uint32
	authToken string
	done      chan struct{}
}

func newSessionManager(port string) *sessionManager {
	return &sessionManager{port: port, sessionID: ^uint32(0), done: make(chan struct{})}
}

// generateAuthToken creates a new random hex token for agent authentication.
func generateAuthToken() string {
	b := make([]byte, agentTokenLen)
	if _, err := crand.Read(b); err != nil {
		log.Warnf("generate agent auth token: %v", err)
		return ""
	}
	return hex.EncodeToString(b)
}

// AuthToken returns the current agent authentication token.
func (m *sessionManager) AuthToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.authToken
}

// Stop signals the session manager to exit its polling loop.
func (m *sessionManager) Stop() {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
}

func (m *sessionManager) run() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		sid := getActiveSessionID()

		m.mu.Lock()
		if sid != m.sessionID {
			log.Infof("active session changed: %d -> %d", m.sessionID, sid)
			m.killAgent()
			m.sessionID = sid
		}

		if m.agentProc != 0 {
			var code uint32
			_ = windows.GetExitCodeProcess(m.agentProc, &code)
			if code != stillActive {
				log.Infof("agent exited (code=%d), respawning", code)
				windows.CloseHandle(m.agentProc)
				m.agentProc = 0
			}
		}

		if m.agentProc == 0 && sid != 0xFFFFFFFF {
			m.authToken = generateAuthToken()
			h, err := spawnAgentInSession(sid, m.port, m.authToken)
			if err != nil {
				log.Warnf("spawn agent in session %d: %v", sid, err)
				m.authToken = ""
			} else {
				m.agentProc = h
			}
		}
		m.mu.Unlock()

		select {
		case <-m.done:
			m.mu.Lock()
			m.killAgent()
			m.mu.Unlock()
			return
		case <-ticker.C:
		}
	}
}

func (m *sessionManager) killAgent() {
	if m.agentProc != 0 {
		_ = windows.TerminateProcess(m.agentProc, 0)
		windows.CloseHandle(m.agentProc)
		m.agentProc = 0
		log.Info("killed old agent")
	}
}

// relogAgentOutput reads JSON log lines from the agent's stderr pipe and
// relogs them at the correct level with the service's formatter.
func relogAgentOutput(pipe windows.Handle) {
	defer windows.CloseHandle(pipe)
	f := os.NewFile(uintptr(pipe), "vnc-agent-stderr")
	defer f.Close()

	entry := log.WithField("component", "vnc-agent")
	dec := json.NewDecoder(f)
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			break
		}
		msg, _ := m["msg"].(string)
		if msg == "" {
			continue
		}

		// Forward extra fields from the agent (skip standard logrus fields).
		// Remap "caller" to "source" so it doesn't conflict with logrus internals
		// but still shows the original file/line from the agent process.
		fields := make(log.Fields)
		for k, v := range m {
			switch k {
			case "msg", "level", "time", "func":
				continue
			case "caller":
				fields["source"] = v
			default:
				fields[k] = v
			}
		}
		e := entry.WithFields(fields)

		switch m["level"] {
		case "error":
			e.Error(msg)
		case "warning":
			e.Warn(msg)
		case "debug":
			e.Debug(msg)
		case "trace":
			e.Trace(msg)
		default:
			e.Info(msg)
		}
	}
}

// proxyToAgent connects to the agent, sends the auth token, then proxies
// the VNC client connection bidirectionally.
func proxyToAgent(client net.Conn, port string, authToken string) {
	defer client.Close()

	addr := "127.0.0.1:" + port
	var agentConn net.Conn
	var err error
	for range 50 {
		agentConn, err = net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		log.Warnf("proxy cannot reach agent at %s: %v", addr, err)
		return
	}
	defer agentConn.Close()

	// Send the auth token so the agent can verify this connection
	// comes from the trusted service process.
	tokenBytes, _ := hex.DecodeString(authToken)
	if _, err := agentConn.Write(tokenBytes); err != nil {
		log.Warnf("send auth token to agent: %v", err)
		return
	}

	log.Debugf("proxy connected to agent, starting bidirectional copy")

	done := make(chan struct{}, 2)
	cp := func(label string, dst, src net.Conn) {
		n, err := io.Copy(dst, src)
		log.Debugf("proxy %s: %d bytes, err=%v", label, n, err)
		done <- struct{}{}
	}
	go cp("client→agent", agentConn, client)
	go cp("agent→client", client, agentConn)
	<-done
}
