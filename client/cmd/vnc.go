package cmd

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/util"
)

var (
	vncUsername  string
	vncHost      string
	vncMode      string
	vncListen    string
	vncNoBrowser bool
	vncNoCache   bool
)

func init() {
	vncCmd.PersistentFlags().StringVar(&vncUsername, "user", "", "OS username for session mode")
	vncCmd.PersistentFlags().StringVar(&vncMode, "mode", "attach", "Connection mode: attach (view current display) or session (virtual desktop)")
	vncCmd.PersistentFlags().StringVar(&vncListen, "listen", "", "Start local VNC proxy on this address (e.g., :5900) for external VNC viewers")
	vncCmd.PersistentFlags().BoolVar(&vncNoBrowser, noBrowserFlag, false, noBrowserDesc)
	vncCmd.PersistentFlags().BoolVar(&vncNoCache, "no-cache", false, "Skip cached JWT token and force fresh authentication")
}

var vncCmd = &cobra.Command{
	Use:   "vnc [flags] [user@]host",
	Short: "Connect to a NetBird peer via VNC",
	Long: `Connect to a NetBird peer using VNC with JWT-based authentication.
The target peer must have the VNC server enabled.

Two modes are available:
  - attach: view the current physical display (remote support)
  - session: start a virtual desktop as the specified user (passwordless login)

Use --listen to start a local proxy for external VNC viewers:
  netbird vnc --listen :5900 peer-hostname
  vncviewer localhost:5900

Examples:
  netbird vnc peer-hostname
  netbird vnc --mode session --user alice peer-hostname
  netbird vnc --listen :5900 peer-hostname`,
	Args: cobra.MinimumNArgs(1),
	RunE: vncFn,
}

func vncFn(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(cmd)
	cmd.SetOut(cmd.OutOrStdout())

	logOutput := "console"
	if firstLogFile := util.FindFirstLogPath(logFiles); firstLogFile != "" && firstLogFile != defaultLogFile {
		logOutput = firstLogFile
	}
	if err := util.InitLog(logLevel, logOutput); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	if err := parseVNCHostArg(args[0]); err != nil {
		return err
	}

	ctx := internal.CtxInitState(cmd.Context())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	vncCtx, cancel := context.WithCancel(ctx)

	errCh := make(chan error, 1)
	go func() {
		if err := runVNC(vncCtx, cmd); err != nil {
			errCh <- err
		}
		cancel()
	}()

	select {
	case <-sig:
		cancel()
		<-vncCtx.Done()
		return nil
	case err := <-errCh:
		return err
	case <-vncCtx.Done():
	}

	return nil
}

func parseVNCHostArg(arg string) error {
	if strings.Contains(arg, "@") {
		parts := strings.SplitN(arg, "@", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid user@host format")
		}
		if vncUsername == "" {
			vncUsername = parts[0]
		}
		vncHost = parts[1]
		if vncMode == "attach" {
			vncMode = "session"
		}
	} else {
		vncHost = arg
	}

	if vncMode == "session" && vncUsername == "" {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			vncUsername = sudoUser
		} else if currentUser, err := user.Current(); err == nil {
			vncUsername = currentUser.Username
		}
	}

	return nil
}

func runVNC(ctx context.Context, cmd *cobra.Command) error {
	grpcAddr := strings.TrimPrefix(daemonAddr, "tcp://")
	grpcConn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer func() { _ = grpcConn.Close() }()

	daemonClient := proto.NewDaemonServiceClient(grpcConn)

	if vncMode == "session" {
		cmd.Printf("Connecting to %s@%s [session mode]...\n", vncUsername, vncHost)
	} else {
		cmd.Printf("Connecting to %s [attach mode]...\n", vncHost)
	}

	// Obtain JWT token. If the daemon has no SSO configured, proceed without one
	// (the server will accept unauthenticated connections if --disable-vnc-auth is set).
	var jwtToken string
	hint := profilemanager.GetLoginHint()
	var browserOpener func(string) error
	if !vncNoBrowser {
		browserOpener = util.OpenBrowser
	}

	token, err := nbssh.RequestJWTToken(ctx, daemonClient, nil, cmd.ErrOrStderr(), !vncNoCache, hint, browserOpener)
	if err != nil {
		log.Debugf("JWT authentication unavailable, connecting without token: %v", err)
	} else {
		jwtToken = token
		log.Debug("JWT authentication successful")
	}

	// Connect to the VNC server on the standard port (5900). The peer's firewall
	// DNATs 5900 -> 25900 (internal), so both ports work on the overlay network.
	vncAddr := net.JoinHostPort(vncHost, "5900")
	vncConn, err := net.DialTimeout("tcp", vncAddr, vncDialTimeout)
	if err != nil {
		return fmt.Errorf("connect to VNC at %s: %w", vncAddr, err)
	}
	defer vncConn.Close()

	// Send session header with mode, username, and JWT.
	if err := sendVNCHeader(vncConn, vncMode, vncUsername, jwtToken); err != nil {
		return fmt.Errorf("send VNC header: %w", err)
	}

	cmd.Printf("VNC connected to %s\n", vncHost)

	if vncListen != "" {
		return runVNCLocalProxy(ctx, cmd, vncConn)
	}

	// No --listen flag: inform the user they need to use --listen for external viewers.
	cmd.Printf("VNC tunnel established. Use --listen :5900 to proxy for local VNC viewers.\n")
	cmd.Printf("Press Ctrl+C to disconnect.\n")
	<-ctx.Done()
	return nil
}

const vncDialTimeout = 15 * time.Second

// sendVNCHeader writes the NetBird VNC session header.
func sendVNCHeader(conn net.Conn, mode, username, jwt string) error {
	var modeByte byte
	if mode == "session" {
		modeByte = 1
	}

	usernameBytes := []byte(username)
	jwtBytes := []byte(jwt)
	hdr := make([]byte, 3+len(usernameBytes)+2+len(jwtBytes))
	hdr[0] = modeByte
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(usernameBytes)))
	off := 3
	copy(hdr[off:], usernameBytes)
	off += len(usernameBytes)
	binary.BigEndian.PutUint16(hdr[off:off+2], uint16(len(jwtBytes)))
	off += 2
	copy(hdr[off:], jwtBytes)

	_, err := conn.Write(hdr)
	return err
}

// runVNCLocalProxy listens on the given address and proxies incoming
// connections to the already-established VNC tunnel.
func runVNCLocalProxy(ctx context.Context, cmd *cobra.Command, vncConn net.Conn) error {
	listener, err := net.Listen("tcp", vncListen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", vncListen, err)
	}
	defer listener.Close()

	cmd.Printf("VNC proxy listening on %s - connect with your VNC viewer\n", listener.Addr())
	cmd.Printf("Press Ctrl+C to stop.\n")

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	// Accept a single viewer connection. VNC is single-session: the RFB
	// handshake completes on vncConn for the first viewer, so subsequent
	// viewers would get a mid-stream connection. The loop handles transient
	// accept errors until a valid connection arrives.
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			log.Debugf("accept VNC proxy client: %v", err)
			continue
		}

		cmd.Printf("VNC viewer connected from %s\n", clientConn.RemoteAddr())

		// Bidirectional copy.
		done := make(chan struct{})
		go func() {
			io.Copy(vncConn, clientConn)
			close(done)
		}()
		io.Copy(clientConn, vncConn)
		<-done
		clientConn.Close()

		cmd.Printf("VNC viewer disconnected\n")
		return nil
	}
}
