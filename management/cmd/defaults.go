package cmd

const (
	defaultMgmtDataDir   = "/opt/var/lib/netbird/"
	defaultMgmtConfigDir = "/opt/etc/netbird"
	defaultLogDir        = "/opt/var/log/netbird"

	oldDefaultMgmtDataDir   = "/opt/var/lib/wiretrustee/"
	oldDefaultMgmtConfigDir = "/opt/etc/wiretrustee"
	oldDefaultLogDir        = "/opt/var/log/wiretrustee"

	defaultMgmtConfig    = defaultMgmtConfigDir + "/management.json"
	defaultLogFile       = defaultLogDir + "/management.log"
	oldDefaultMgmtConfig = oldDefaultMgmtConfigDir + "/management.json"
	oldDefaultLogFile    = oldDefaultLogDir + "/management.log"

	defaultSingleAccModeDomain = "netbird.selfhosted"
)
