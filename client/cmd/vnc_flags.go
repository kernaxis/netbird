package cmd

const (
	serverVNCAllowedFlag = "allow-server-vnc"
	disableVNCAuthFlag   = "disable-vnc-auth"
)

var (
	serverVNCAllowed bool
	disableVNCAuth   bool
)

func init() {
	upCmd.PersistentFlags().BoolVar(&serverVNCAllowed, serverVNCAllowedFlag, false, "Allow embedded VNC server on peer")
	upCmd.PersistentFlags().BoolVar(&disableVNCAuth, disableVNCAuthFlag, false, "Disable JWT authentication for VNC")
}
