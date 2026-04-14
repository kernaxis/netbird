//go:build windows

package cmd

import (
	"net/netip"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

var vncAgentPort string

func init() {
	vncAgentCmd.Flags().StringVar(&vncAgentPort, "port", "15900", "Port for the VNC agent to listen on")
	rootCmd.AddCommand(vncAgentCmd)
}

// vncAgentCmd runs a VNC server in the current user session, listening on
// localhost. It is spawned by the NetBird service (Session 0) via
// CreateProcessAsUser into the interactive console session.
var vncAgentCmd = &cobra.Command{
	Use:    "vnc-agent",
	Short:  "Run VNC capture agent (internal, spawned by service)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Agent's stderr is piped to the service which relogs it.
		// Use JSON format with caller info for structured parsing.
		log.SetReportCaller(true)
		log.SetFormatter(&log.JSONFormatter{})
		log.SetOutput(os.Stderr)

		sessionID := vncserver.GetCurrentSessionID()
		log.Infof("VNC agent starting on 127.0.0.1:%s (session %d)", vncAgentPort, sessionID)

		capturer := vncserver.NewDesktopCapturer()
		injector := vncserver.NewWindowsInputInjector()
		srv := vncserver.New(capturer, injector, "")
		// Auth is handled by the service. The agent verifies a token on each
		// connection to ensure only the service process can connect.
		// The token is passed via environment variable to avoid exposing it
		// in the process command line (visible via tasklist/wmic).
		srv.SetDisableAuth(true)
		srv.SetAgentToken(os.Getenv("NB_VNC_AGENT_TOKEN"))

		port, err := netip.ParseAddrPort("127.0.0.1:" + vncAgentPort)
		if err != nil {
			return err
		}

		loopback := netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 0}), 8)
		if err := srv.Start(cmd.Context(), port, loopback); err != nil {
			return err
		}

		<-cmd.Context().Done()
		return srv.Stop()
	},
}
