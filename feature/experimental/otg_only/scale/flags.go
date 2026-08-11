package scale

import (
	"flag"
	"time"
)

// The library owns only the flags describing how to reach the rig and how to
// read telemetry. Every flag describing the scale or the shape of a run --
// -scale_sessions, -scale_routes, -scale_traffic, the addressing and VLAN
// flags -- belongs to the test that defines what it is running.
var (
	// Ixia chassis / card discovery. The rated session and flow limits depend on
	// the card behind the bound ports and on how its resource groups are broken
	// out, so they are read off the chassis rather than assumed.
	chassisCheck   = flag.Bool("scale_chassis_check", false, "discover the Ixia card behind the bound ports and warn when the requested scale exceeds its rated session/flow limits")
	chassisUser    = flag.String("scale_chassis_user", "admin", "IxOS chassis username, for card discovery")
	chassisPass    = flag.String("scale_chassis_pass", "admin", "IxOS chassis password, for card discovery")
	chassisTimeout = flag.Duration("scale_chassis_timeout", 30*time.Second, "per-request timeout for the IxOS chassis SSH / REST calls")
	limitsFile     = flag.String("scale_limits_file", "", "path to a card_limits.json overriding the built-in rating matrix (default: card_limits.json next to the test, then in its parent directory)")

	// Port reboot. Mandatory, so there is no flag to disable it; only the waits
	// are tunable.
	portRebootTimeout = flag.Duration("scale_port_reboot_timeout", 10*time.Minute, "max time to wait for the ports to come back after the pre-iteration port reboot")
	portRebootSettle  = flag.Duration("scale_port_reboot_settle", 30*time.Second, "how long to let a reboot take effect before polling the ports for their link state")

	// Telemetry method. Falls back permanently to per-peer queries the first time
	// the wildcard query returns nothing.
	useWildcard = flag.Bool("scale_wildcard_telemetry", true, "fetch BGP peer telemetry with one wildcard (BgpPeerAny) query instead of per-peer queries")
)
