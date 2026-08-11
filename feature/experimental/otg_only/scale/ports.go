package scale

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	otg "github.com/openconfig/ondatra/otg"
)

// SeedPortConfig pushes a config holding nothing but the ports under test and
// returns their OTG names. The reboot action names configured ports, so this
// makes them nameable from the first iteration onwards.
func SeedPortConfig(t *testing.T, otgDev *otg.OTG) []string {
	t.Helper()
	cfg := gosnappi.NewConfig()
	names := []string{"port1", "port2"}
	for _, name := range names {
		cfg.Ports().Add().SetName(name)
	}
	t.Logf("Seeding the ATE with a ports-only config (%v) so the ports can be rebooted over the OTG API...", names)
	APITime.Call(t, APISetConfig, func() { otgDev.PushConfig(t, cfg) })
	return names
}

// RebootPorts reboots the named ports and blocks until they are back, so an
// iteration starts from a known port state rather than inheriting the previous
// one's devices. The reboot is an OTG control action (ActionPortReboot) and
// readiness is read back over OTG telemetry, so the whole step needs only the
// controller connection. portNames comes from SeedPortConfig.
func RebootPorts(t *testing.T, ate *ondatra.ATEDevice, portNames []string) {
	t.Helper()
	if len(portNames) == 0 {
		t.Fatal("port reboot: no OTG ports to reboot; SeedPortConfig must run before the first reboot")
	}
	start := time.Now()

	act := gosnappi.NewControlAction()
	act.Port().Reboot().SetPortNames(portNames)

	t.Logf("rebooting ports %v...", portNames)
	APITime.Call(t, APIPortReboot, func() { ate.OTG().SetControlAction(t, act) })

	awaitPortsReady(t, ate, portNames, start)
}

// awaitPortsReady polls port link telemetry until every port is up again. A port
// reporting DOWN, or reporting nothing yet, counts as not back.
func awaitPortsReady(t *testing.T, ate *ondatra.ATEDevice, portNames []string, start time.Time) {
	t.Helper()
	deadline := time.Now().Add(*portRebootTimeout)

	// Let the reboot take effect before the first poll.
	time.Sleep(*portRebootSettle)

	for {
		fetchStart := time.Now()
		up, states := 0, make([]string, 0, len(portNames))
		for _, name := range portNames {
			v, ok := gnmi.Lookup(t, ate.OTG(), gnmi.OTG().Port(name).Link().State()).Val()
			switch {
			case !ok:
				states = append(states, fmt.Sprintf("%s=no state", name))
			case v == otgtelemetry.Port_Link_UP:
				up++
				states = append(states, fmt.Sprintf("%s=%s", name, v))
			default:
				states = append(states, fmt.Sprintf("%s=%s", name, v))
			}
		}
		took := APITime.Track(APIGetPortLink, fetchStart)

		t.Logf("[t+%-6v] ports back after reboot: %d/%d (%s) in %v",
			time.Since(start).Truncate(time.Second), up, len(portNames),
			strings.Join(states, ", "), took.Round(time.Millisecond))

		if up == len(portNames) {
			t.Logf("port reboot complete in %v", time.Since(start).Truncate(time.Second))
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port reboot: timed out after %v waiting for the ports to come back (%d/%d up: %s)",
				*portRebootTimeout, up, len(portNames), strings.Join(states, ", "))
		}
		time.Sleep(10 * time.Second)
	}
}
