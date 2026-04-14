//go:build js

package vnc

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	vncProxyHost   = "vnc.proxy.local"
	vncProxyScheme = "ws"
	vncDialTimeout = 15 * time.Second

	// Connection modes matching server/server.go constants.
	modeAttach  byte = 0
	modeSession byte = 1
)

// VNCProxy bridges WebSocket connections from noVNC in the browser
// to TCP VNC server connections through the NetBird tunnel.
type VNCProxy struct {
	nbClient interface {
		Dial(ctx context.Context, network, address string) (net.Conn, error)
	}
	activeConnections map[string]*vncConnection
	destinations      map[string]vncDestination
	mu                sync.Mutex
	nextID            atomic.Uint64
}

type vncDestination struct {
	address   string
	mode      byte
	username  string
	jwt       string
	sessionID uint32 // Windows session ID (0 = auto/console)
}

type vncConnection struct {
	id          string
	destination vncDestination
	mu          sync.Mutex
	vncConn     net.Conn
	wsHandlers  js.Value
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewVNCProxy creates a new VNC proxy.
func NewVNCProxy(client interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}) *VNCProxy {
	return &VNCProxy{
		nbClient:          client,
		activeConnections: make(map[string]*vncConnection),
	}
}

// CreateProxy creates a new proxy endpoint for the given VNC destination.
// mode is "attach" (capture current display) or "session" (virtual session).
// username is required for session mode.
// Returns a JS Promise that resolves to the WebSocket proxy URL.
func (p *VNCProxy) CreateProxy(hostname, port, mode, username, jwt string, sessionID uint32) js.Value {
	address := fmt.Sprintf("%s:%s", hostname, port)

	var m byte
	if mode == "session" {
		m = modeSession
	}

	dest := vncDestination{
		address:   address,
		mode:      m,
		username:  username,
		jwt:       jwt,
		sessionID: sessionID,
	}

	return js.Global().Get("Promise").New(js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve := args[0]

		go func() {
			proxyID := fmt.Sprintf("vnc_proxy_%d", p.nextID.Add(1))

			p.mu.Lock()
			if p.destinations == nil {
				p.destinations = make(map[string]vncDestination)
			}
			p.destinations[proxyID] = dest
			p.mu.Unlock()

			proxyURL := fmt.Sprintf("%s://%s/%s", vncProxyScheme, vncProxyHost, proxyID)

			js.Global().Set(fmt.Sprintf("handleVNCWebSocket_%s", proxyID), js.FuncOf(func(_ js.Value, args []js.Value) any {
				if len(args) < 1 {
					return js.ValueOf("error: requires WebSocket argument")
				}
				ws := args[0]
				p.handleWebSocketConnection(ws, proxyID)
				return nil
			}))

			log.Infof("created VNC proxy: %s -> %s (mode=%s, user=%s)", proxyURL, address, mode, username)
			resolve.Invoke(proxyURL)
		}()

		return nil
	}))
}

func (p *VNCProxy) handleWebSocketConnection(ws js.Value, proxyID string) {
	p.mu.Lock()
	dest, ok := p.destinations[proxyID]
	p.mu.Unlock()

	if !ok {
		log.Errorf("no destination for VNC proxy %s", proxyID)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	conn := &vncConnection{
		id:          proxyID,
		destination: dest,
		wsHandlers:  ws,
		ctx:         ctx,
		cancel:      cancel,
	}

	p.mu.Lock()
	p.activeConnections[proxyID] = conn
	p.mu.Unlock()

	p.setupWebSocketHandlers(ws, conn)
	go p.connectToVNC(conn)

	log.Infof("VNC proxy WebSocket connection established for %s", proxyID)
}

func (p *VNCProxy) setupWebSocketHandlers(ws js.Value, conn *vncConnection) {
	ws.Set("onGoMessage", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return nil
		}
		data := args[0]
		go p.handleWebSocketMessage(conn, data)
		return nil
	}))

	ws.Set("onGoClose", js.FuncOf(func(_ js.Value, _ []js.Value) any {
		log.Debug("VNC WebSocket closed by JavaScript")
		conn.cancel()
		return nil
	}))
}

func (p *VNCProxy) handleWebSocketMessage(conn *vncConnection, data js.Value) {
	if !data.InstanceOf(js.Global().Get("Uint8Array")) {
		return
	}

	length := data.Get("length").Int()
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, data)

	conn.mu.Lock()
	vncConn := conn.vncConn
	conn.mu.Unlock()

	if vncConn == nil {
		return
	}

	if _, err := vncConn.Write(buf); err != nil {
		log.Debugf("write to VNC server: %v", err)
	}
}

func (p *VNCProxy) connectToVNC(conn *vncConnection) {
	ctx, cancel := context.WithTimeout(conn.ctx, vncDialTimeout)
	defer cancel()

	vncConn, err := p.nbClient.Dial(ctx, "tcp", conn.destination.address)
	if err != nil {
		log.Errorf("VNC connect to %s: %v", conn.destination.address, err)
		// Close the WebSocket so noVNC fires a disconnect event.
		if conn.wsHandlers.Get("close").Truthy() {
			conn.wsHandlers.Call("close", 1006, fmt.Sprintf("connect to peer: %v", err))
		}
		p.cleanupConnection(conn)
		return
	}
	conn.mu.Lock()
	conn.vncConn = vncConn
	conn.mu.Unlock()

	// Send the NetBird VNC session header before the RFB handshake.
	if err := p.sendSessionHeader(vncConn, conn.destination); err != nil {
		log.Errorf("send VNC session header: %v", err)
		p.cleanupConnection(conn)
		return
	}

	// WS→TCP is handled by the onGoMessage handler set in setupWebSocketHandlers,
	// which writes directly to the VNC connection as data arrives from JS.
	// Only the TCP→WS direction needs a read loop here.
	go p.forwardConnToWS(conn)

	<-conn.ctx.Done()
	p.cleanupConnection(conn)
}

// sendSessionHeader writes mode, username, and JWT to the VNC server.
// Format: [mode: 1 byte] [username_len: 2 bytes BE] [username: N bytes]
//
//	[jwt_len: 2 bytes BE] [jwt: N bytes]
func (p *VNCProxy) sendSessionHeader(conn net.Conn, dest vncDestination) error {
	usernameBytes := []byte(dest.username)
	jwtBytes := []byte(dest.jwt)
	// Format: [mode:1] [username_len:2] [username:N] [jwt_len:2] [jwt:N] [session_id:4]
	hdr := make([]byte, 3+len(usernameBytes)+2+len(jwtBytes)+4)
	hdr[0] = dest.mode
	hdr[1] = byte(len(usernameBytes) >> 8)
	hdr[2] = byte(len(usernameBytes))
	off := 3
	copy(hdr[off:], usernameBytes)
	off += len(usernameBytes)
	hdr[off] = byte(len(jwtBytes) >> 8)
	hdr[off+1] = byte(len(jwtBytes))
	off += 2
	copy(hdr[off:], jwtBytes)
	off += len(jwtBytes)
	hdr[off] = byte(dest.sessionID >> 24)
	hdr[off+1] = byte(dest.sessionID >> 16)
	hdr[off+2] = byte(dest.sessionID >> 8)
	hdr[off+3] = byte(dest.sessionID)

	_, err := conn.Write(hdr)
	return err
}

func (p *VNCProxy) forwardConnToWS(conn *vncConnection) {
	buf := make([]byte, 32*1024)

	for {
		if conn.ctx.Err() != nil {
			return
		}

		// Set a read deadline so we detect dead connections instead of
		// blocking forever when the remote peer dies.
		conn.mu.Lock()
		vc := conn.vncConn
		conn.mu.Unlock()
		if vc == nil {
			return
		}
		vc.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := vc.Read(buf)
		if err != nil {
			if conn.ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				// Read timeout: connection might be stale. Send a ping-like
				// empty read to check. If the connection is truly dead, the
				// next iteration will fail too and we'll close.
				continue
			}
			if err != io.EOF {
				log.Debugf("read from VNC connection: %v", err)
			}
			// Close the WebSocket to notify noVNC.
			if conn.wsHandlers.Get("close").Truthy() {
				conn.wsHandlers.Call("close", 1006, "VNC connection lost")
			}
			return
		}

		if n > 0 {
			p.sendToWebSocket(conn, buf[:n])
		}
	}
}

func (p *VNCProxy) sendToWebSocket(conn *vncConnection, data []byte) {
	if conn.wsHandlers.Get("receiveFromGo").Truthy() {
		uint8Array := js.Global().Get("Uint8Array").New(len(data))
		js.CopyBytesToJS(uint8Array, data)
		conn.wsHandlers.Call("receiveFromGo", uint8Array.Get("buffer"))
	} else if conn.wsHandlers.Get("send").Truthy() {
		uint8Array := js.Global().Get("Uint8Array").New(len(data))
		js.CopyBytesToJS(uint8Array, data)
		conn.wsHandlers.Call("send", uint8Array.Get("buffer"))
	}
}

func (p *VNCProxy) cleanupConnection(conn *vncConnection) {
	log.Debugf("cleaning up VNC connection %s", conn.id)
	conn.cancel()

	conn.mu.Lock()
	vncConn := conn.vncConn
	conn.vncConn = nil
	conn.mu.Unlock()

	if vncConn != nil {
		if err := vncConn.Close(); err != nil {
			log.Debugf("close VNC connection: %v", err)
		}
	}

	// Remove the global JS handler registered in CreateProxy.
	globalName := fmt.Sprintf("handleVNCWebSocket_%s", conn.id)
	js.Global().Delete(globalName)

	p.mu.Lock()
	delete(p.activeConnections, conn.id)
	delete(p.destinations, conn.id)
	p.mu.Unlock()
}
