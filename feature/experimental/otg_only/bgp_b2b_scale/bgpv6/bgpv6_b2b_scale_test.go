// Package otg_b2b_bgpv6_scale is an OTG-only (ATE port1 <-> ATE port2 back-to-back)
// BGPv6 session scale test written against the featureprofiles/ondatra framework.
//
// It mirrors ../bgpv4/bgpv4_b2b_scale_test.go, but configures BGPv6 peers over
// IPv6 interfaces (Ipv6Interfaces / BgpV6Peer / V6Routes) instead of v4. It uses only
// ondatra + gosnappi + OTG gNMI telemetry, exactly like the reference b2b test in
// ../bgp_b2b/otgb2b_bgp_test.go.
//
// N BGPv6 sessions are brought up on each port (2*N peers total, each port1 peer
// paired with the port2 peer facing it), every peer advertises a /128 route range,
// and session state / route counters are read back over OTG gNMI (BgpPeer telemetry
// is AFI-agnostic, so the same paths serve v4 and v6 peers). A capped number of
// data-plane flows over the advertised route ranges is used as a sanity check.
//
// Every device is double tagged (outer QinQ + inner dot1q) with a per-session tag
// pair, as in the Athena scale test, so each session pair sits in its own broadcast
// domain; the port L1 MTU is raised to carry those tags. All peers are iBGP in one
// AS, and each peer's router ID is a real (unique, non-zero) IPv4 address. Tagging
// (-scale_vlan / -scale_qinq) and the non-default BGP TCP ports
// (-scale_listen_port / -scale_neighbor_port) are optional.
//
// Before anything is pushed, the test resolves the ports named in the binding
// ("<chassis>;<card>;<port>") to the real Ixia card and resource group behind them,
// and warns -- loudly, and again in the run summary -- when the requested scale is
// above what that card is rated for. The rating depends on the resource group
// layout, not just the card: an AresONE S400GD-16P-QDD group broken out 2x400G is
// rated for 13491 BGPv6 sessions per port, the same card broken out 16x50G for only
// 1686. Note the v6 column is the tighter one -- the same group carries 18278 v4
// sessions. Per-port memory / PCPU status and chassis CPU / memory are logged before
// each iteration and again at full scale. This needs the chassis credentials
// (-scale_chassis_user / -scale_chassis_pass, default admin/admin); pass
// -scale_chassis_check=false to skip discovery entirely.
//
// Every OTG API call is timed. One-shot calls (SetConfig, StartProtocols,
// StartTransmit, StopTransmit, StopProtocols) are highlighted with a ">>> OTG API"
// line as they happen, the GetMetrics fetches behind the poll loops are aggregated,
// and each iteration ends with a table of all of them.
//
// Run (10 sessions per port):
//
//	go test -v ./feature/experimental/otg_only/bgp_b2b_scale/bgpv6/bgpv6_b2b_scale_test.go -timeout 60m \
//	  -binding <path>/otgb2b-hw.binding -testbed <path>/otgb2b-hw.testbed \
//	  -scale_sessions=10 | tee bgpv6_b2b_scale_10.log
//
// Then repeat with -scale_sessions=100 / 1000 / 10000 (raise -scale_session_timeout
// for the larger counts).
package otg_b2b_bgpv6_scale

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	otg "github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
	"golang.org/x/crypto/ssh"
)

var (
	numSessions    = flag.Uint("scale_sessions", 10, "number of BGPv6 sessions per port (total peers = 2 x this)")
	routesPerPeer  = flag.Uint("scale_routes", 1, "number of /128 routes advertised by each peer")
	iterations     = flag.Uint("scale_iterations", 1, "number of config-push/session-up/traffic iterations to run")
	sessionTimeout = flag.Duration("scale_session_timeout", 30*time.Minute, "max time to wait for all sessions to reach ESTABLISHED")
	metricsTimeout = flag.Duration("scale_metrics_timeout", 5*time.Minute, "max time to wait for BGP route counters to settle")
	runTraffic     = flag.Bool("scale_traffic", true, "run the data-plane sanity-check flows")
	trafficTimeout = flag.Duration("scale_traffic_timeout", 60*time.Minute, "max time to wait for every flow to finish transmitting its packet count")
	maxFlows       = flag.Uint("scale_max_flows", 256, "cap on the number of data-plane flows; also checked against the card's rated flow capacity")
	flowPackets    = flag.Uint("scale_flow_packets", 1000, "fixed packet count per flow")
	flowPps        = flag.Uint("scale_flow_pps", 500, "packets per second per flow")
	flowSize       = flag.Uint("scale_flow_size", 100, "frame size of the sanity-check flows")
	useWildcard    = flag.Bool("scale_wildcard_telemetry", true, "fetch BGP peer telemetry with one wildcard (BgpPeerAny) query instead of per-peer queries")
	dumpConfig     = flag.Bool("scale_dump_config", false, "log the pushed OTG config as JSON")

	// Ixia chassis / card discovery. What this rig can actually carry depends on
	// the card behind the bound ports and on how that card's resource groups are
	// broken out, so the limits are read off the chassis instead of assumed: an
	// AresONE S400GD-16P-QDD group split 2x400G is rated for 13491 BGPv6 sessions
	// per port, the same group split 16x50G for only 1686.
	chassisCheck   = flag.Bool("scale_chassis_check", false, "discover the Ixia card behind the bound ports and warn when the requested scale exceeds its rated session/flow limits")
	chassisUser    = flag.String("scale_chassis_user", "admin", "IxOS chassis username, for card discovery")
	chassisPass    = flag.String("scale_chassis_pass", "admin", "IxOS chassis password, for card discovery")
	chassisTimeout = flag.Duration("scale_chassis_timeout", 30*time.Second, "per-request timeout for the IxOS chassis SSH / REST calls")
	limitsFile     = flag.String("scale_limits_file", "", "path to a card_limits.json overriding the built-in rating matrix (default: card_limits.json next to the test, then in its parent directory)")

	// Port reboot. Off by default: it costs minutes, and it is only worth paying
	// when a measurement has to start from a known port state rather than
	// inheriting whatever the previous run left behind. Needs the chassis REST
	// API, so it cannot run against a chassis still on a default password.
	portReboot        = flag.Bool("scale_port_reboot", true, "reboot the ports under test over the IxOS REST API once at the start, before any config is pushed")
	portRebootTimeout = flag.Duration("scale_port_reboot_timeout", 10*time.Minute, "max time to wait for the ports to come back after -scale_port_reboot")

	// Addressing. Every session pair gets its OWN /64: session i sits in
	// <subnetBase with the 4th hextet set to i>::/64, with ::1 on port1 and ::2 on
	// port2, and each side uses the other as gateway / BGP peer.
	//
	// One subnet per session (and therefore per VLAN) is required, not cosmetic: on
	// this rig ixia-c answers neighbor discovery for a subnet from a single device,
	// so sharing one subnet across all devices leaves every device but the first
	// without a neighbor entry, and `start flows` then refuses to resolve the flow
	// dst MAC.
	subnetBase = flag.String("scale_subnet_base", "2001:db8::", "base of the per-session /64 subnets; session i uses the 4th hextet as its subnet id")
	ipPrefix   = flag.Uint("scale_ip_prefix", 64, "prefix length of the per-session interface subnets")
	asNum      = flag.Uint("scale_as", 65000, "BGP AS number; all peers are iBGP in this single AS")

	// BGP router IDs. A router ID is a 4-byte value (the OTG model validates it as
	// an IPv4 address), so a v6-only device cannot use its interface address
	// verbatim. Each router ID instead mirrors the device's subnet: it is the
	// session index added to a real IPv4 base, so port1 device i in
	// 2001:db8:0:i::/64 gets router ID 10.1.0.i. The two bases keep the sides
	// distinct (a duplicate router ID between the peers of a pair is a protocol
	// violation and is rejected after Open).
	p1RouterID = flag.String("scale_p1_router_id", "10.1.0.0", "port1 BGP router ID base; the session index is added to it")
	p2RouterID = flag.String("scale_p2_router_id", "10.2.0.0", "port2 BGP router ID base; the session index is added to it")

	// VLAN encapsulation. Each session index gets its own tag pair, shared by the
	// paired port1/port2 devices, so every session pair is its own L2 domain.
	vlanTagging = flag.Bool("scale_vlan", true, "tag every device with a per-session dot1q VLAN")
	qinqTagging = flag.Bool("scale_qinq", true, "add an outer QinQ tag on top of the dot1q VLAN (requires -scale_vlan)")
	l1MTU       = flag.Uint("scale_l1_mtu", 1516, "port layer1 MTU; the default carries the two VLAN tags on top of the 1500 byte device MTU (the Athena BGPv6 scale test used 1504)")

	// Optional non-default BGP TCP ports. Both must be set to take effect; the two
	// sides mirror each other, so what port1 listens on is what port2 connects to.
	listenPort   = flag.Uint("scale_listen_port", 0, "non-default BGP listen port on port1 peers (0 = leave the default 179)")
	neighborPort = flag.Uint("scale_neighbor_port", 0, "non-default BGP neighbor port on port1 peers (0 = leave the default 179)")
)

const (
	p1MACStart = "02:00:01:00:00:01"
	p2MACStart = "02:00:02:00:00:01"

	// Advertised route range bases, one contiguous block per peer.
	p1RouteStart = "2001:db8:100::1"
	p2RouteStart = "2001:db8:200::1"
	routePrefix  = 128

	// Per-device ethernet MTU, as in the Athena scale test.
	ethMTU = 1500

	tolerancePct = 2.0
	// Loss tolerance in packets, matching the reference b2b test.
	tolerancePkts = 50
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// peerNames holds the configured peer names per side, in device order.
type scaleConfig struct {
	config    gosnappi.Config
	peers     []string // all configured BGPv6 peer names, both ports
	flowNames []string
}

func TestBGPv6B2BScale(t *testing.T) {
	sessions := uint32(*numSessions)
	routes := uint32(*routesPerPeer)
	if sessions == 0 {
		t.Fatal("-scale_sessions must be > 0")
	}

	ate := ondatra.ATE(t, "ate")
	otgDev := ate.OTG()

	// Warnings are repeated at the end of the run, where a scale run's log is
	// long enough that the originals are easy to miss.
	defer logWarnings(t)

	// Resolve the bound ports to a real card and resource group, and warn when
	// the requested scale is above what the card is rated for. afi 6 checks the
	// v6 column, which is the tighter of the two.
	inv := discoverChassis(t, ate)
	checkCardLimits(t, inv, sessions, 6)

	// Optional: start from a known port state rather than inheriting the
	// previous run's. Before any config is pushed.
	rebootPorts(t, inv)

	for itr := uint(0); itr < *iterations; itr++ {
		t.Logf("=== iteration %d/%d : %d sessions/port (%d peers total), %d routes/peer ===",
			itr+1, *iterations, sessions, 2*sessions, routes)
		start := time.Now()
		apiTime.Reset()

		logCardHealth(t, inv, fmt.Sprintf("iteration %d, before config", itr+1))

		sc := buildScaleConfig(t, sessions, routes)

		if *dumpConfig {
			if j, err := sc.config.Marshal().ToJson(); err == nil {
				t.Logf("OTG config:\n%s", j)
			}
		}

		t.Logf("Pushing config to ATE (%d devices, %d peers, %d flows)...",
			len(sc.config.Devices().Items()), len(sc.peers), len(sc.flowNames))
		apiTime.call(t, apiSetConfig, func() { otgDev.PushConfig(t, sc.config) })
		apiTime.call(t, apiStartProtocols, func() { otgDev.StartProtocols(t) })

		logPortAndArpState(t, otgDev, sc.config, 10)

		upStart := time.Now()
		awaitSessionsEstablished(t, otgDev, sc.peers, *sessionTimeout)
		t.Logf("All %d BGPv6 sessions ESTABLISHED in %v", len(sc.peers), time.Since(upStart))

		verifyBGPCounters(t, otgDev, sc.peers, sessions, routes, *metricsTimeout)

		if *runTraffic && len(sc.flowNames) > 0 {
			sendTraffic(t, otgDev, sc.flowNames)
			verifyTraffic(t, otgDev, sc.flowNames)
		}

		// Sampled while the sessions are still up, so the figures reflect the
		// loaded card rather than an idle one.
		logCardHealth(t, inv, fmt.Sprintf("iteration %d, at full scale", itr+1))

		apiTime.call(t, apiStopProtocols, func() { otgDev.StopProtocols(t) })

		t.Log(apiTime.String(fmt.Sprintf("iteration %d/%d, %d sessions/port", itr+1, *iterations, sessions)))
		t.Logf("=== iteration %d/%d completed in %v ===", itr+1, *iterations, time.Since(start))
	}
}

// discoverChassis resolves the bound ATE ports to the Ixia chassis, card and
// resource group they physically live on, and logs what it found. It returns
// nil when -scale_chassis_check=false.
//
// The ports are named "<chassis>;<card>;<port>" in the binding, so the chassis
// is reachable from the port name alone; only the credentials are extra.
func discoverChassis(t *testing.T, ate *ondatra.ATEDevice) *chassisInventory {
	t.Helper()
	if !*chassisCheck {
		t.Log("card discovery disabled (-scale_chassis_check=false); no card limits enforced")
		return nil
	}
	var names []string
	for _, id := range []string{"port1", "port2"} {
		names = append(names, ate.Port(t, id).Name())
	}
	tbl := loadCardLimits(t)
	inv, err := discoverPorts(*chassisUser, *chassisPass, names, *chassisTimeout, tbl)
	if err != nil {
		t.Fatalf("cannot discover the Ixia card behind ports %v: %v\n"+
			"\tset -scale_chassis_user/-scale_chassis_pass, or pass -scale_chassis_check=false to run without card limit enforcement",
			names, err)
	}
	t.Log(inv.String())
	return inv
}

// checkCardLimits warns when the requested scale exceeds what the discovered
// card is rated for. afi is the address family, 4 or 6.
//
// This is a warning, not a failure: an over-rating run is a legitimate thing to
// ask for, and clamping the scale silently would be worse than either -- it
// would report a pass for a scale that was never reached. The run goes ahead at
// exactly the scale asked for, but the warning is highlighted where it happens
// and repeated in the end-of-run summary, so a pass above the card's rating is
// never mistaken for a pass within it.
func checkCardLimits(t *testing.T, inv *chassisInventory, sessions uint32, afi int) {
	t.Helper()
	if inv == nil {
		return
	}
	lim := inv.MinLimits()

	switch want := lim.Sessions(afi); {
	case want == 0:
		t.Logf("card has no published BGPv%d session rating (%s); running %d sessions/port unchecked",
			afi, lim.Source, sessions)
	case sessions > want:
		warnf(t, "-scale_sessions=%d exceeds the %d BGPv%d sessions/port this card is rated for (%s)",
			sessions, want, afi, lim.Source)
	default:
		t.Logf("requested %d BGPv%d sessions/port, within the card's rated %d (%s)",
			sessions, afi, want, lim.Source)
		// Both ports of a b2b pair often sit in one resource group, in which case
		// the group carries the sum of the two sides.
		if inv.SameResourceGroup() && 2*sessions > want {
			warnf(t, "both ports share one resource group, so it carries %d sessions in total, above the %d rated for a single port",
				2*sessions, want)
		}
	}

	if !*runTraffic {
		return
	}
	switch {
	case lim.MaxFlows == 0:
		t.Logf("card has no published flow rating; running with -scale_max_flows=%d unchecked", *maxFlows)
	case uint32(*maxFlows) > lim.MaxFlows:
		warnf(t, "-scale_max_flows=%d exceeds the %d concurrent flows this card is rated for (%s)",
			*maxFlows, lim.MaxFlows, lim.Source)
	default:
		t.Logf("-scale_max_flows=%d, within the card's rated %d", *maxFlows, lim.MaxFlows)
	}
}

// scaleWarnings collects every limit warning raised during the run, so they can
// be repeated at the end where they will not be lost in a scale run's log.
var scaleWarnings []string

// warnf highlights a warning at the point it is raised and remembers it for the
// end-of-run summary. It does not fail the test.
func warnf(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	scaleWarnings = append(scaleWarnings, msg)
	border := strings.Repeat("*", 78)
	t.Logf("\n%s\n*** WARNING: %s\n%s", border, msg, border)
}

// logWarnings repeats every warning raised during the run. Deferred, so it runs
// even when a later step fails the test.
func logWarnings(t *testing.T) {
	t.Helper()
	if len(scaleWarnings) == 0 {
		return
	}
	border := strings.Repeat("*", 78)
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s\n*** %d WARNING(S) RAISED DURING THIS RUN\n%s\n", border, len(scaleWarnings), border)
	for i, w := range scaleWarnings {
		fmt.Fprintf(&b, "*** %2d. %s\n", i+1, w)
	}
	fmt.Fprintf(&b, "%s\n", border)
	t.Log(b.String())
}

// rebootPorts reboots the ports under test and waits for their PCPUs to come
// back, so a run starts from a known port state instead of inheriting whatever
// the previous run left behind.
//
// This is off by default (-scale_port_reboot): it costs minutes, and it is only
// worth paying when a measurement has to be clean -- a scale ladder, or chasing
// a regression where a previous run's residue is a plausible cause. It runs once
// at the start of the test, before any config is pushed.
//
// The reboot is issued over the IxOS REST API, keyed by the port's REST resource
// id (not its card/port number), so it needs REST to be reachable: a chassis
// still on a default password refuses to issue an API session and this cannot
// run there. Failures are fatal -- the request was explicit, and silently
// running on un-rebooted ports would answer a different question than the one
// being asked.
func rebootPorts(t *testing.T, inv *chassisInventory) {
	t.Helper()
	if inv == nil || !*portReboot {
		return
	}
	start := time.Now()

	// Group by chassis so one REST session serves all of that chassis's ports.
	byHost := map[string][]resolvedPort{}
	var hosts []string
	for _, p := range inv.Ports {
		if _, ok := byHost[p.Ref.Chassis]; !ok {
			hosts = append(hosts, p.Ref.Chassis)
		}
		byHost[p.Ref.Chassis] = append(byHost[p.Ref.Chassis], p)
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		r, err := newIxosREST(host, *chassisUser, *chassisPass, *chassisTimeout)
		if err != nil {
			t.Fatalf("port reboot: cannot open a REST session to %s: %v\n"+
				"\tpass -scale_port_reboot=false to run without rebooting the ports", host, err)
		}
		for _, p := range byHost[host] {
			if p.Health == nil || p.Health.RestID == 0 {
				t.Fatalf("port reboot: no REST resource id for port %s; the chassis port list did not report it", p.Ref)
			}
			t.Logf("rebooting port %s (REST id %d)...", p.Ref, p.Health.RestID)
			if err := r.post(fmt.Sprintf("ixos/ports/%d/operations/reboot", p.Health.RestID), nil); err != nil {
				t.Fatalf("port reboot: %s: %v", p.Ref, err)
			}
		}
	}

	awaitPortsReady(t, inv, start)
}

// awaitPortsReady polls the chassis until every port under test reports its PCPU
// ready again. A rebooting port drops out of the port list or reports a
// non-ready PCPU state, so both are treated as "not back yet".
func awaitPortsReady(t *testing.T, inv *chassisInventory, start time.Time) {
	t.Helper()
	const readyState = "PCPUREADY"
	deadline := time.Now().Add(*portRebootTimeout)

	// The reboot is not instant to take effect; polling immediately can catch
	// the ports still reporting ready from before the request landed.
	time.Sleep(15 * time.Second)

	refs := make([]portRef, 0, len(inv.Ports))
	for _, p := range inv.Ports {
		refs = append(refs, p.Ref)
	}

	for {
		health, err := fetchPortHealthFor(*chassisUser, *chassisPass, refs, *chassisTimeout)
		ready, states := 0, make([]string, 0, len(refs))
		if err == nil {
			for _, r := range refs {
				h, ok := health[r.String()]
				switch {
				case !ok:
					states = append(states, fmt.Sprintf("%s=absent", r))
				case strings.EqualFold(h.PcpuStatus, readyState):
					ready++
					states = append(states, fmt.Sprintf("%s=%s/%s", r, h.PcpuStatus, h.LinkState))
				default:
					states = append(states, fmt.Sprintf("%s=%s", r, h.PcpuStatus))
				}
			}
		} else {
			states = append(states, fmt.Sprintf("chassis unreachable: %v", err))
		}

		t.Logf("[t+%-6v] ports back after reboot: %d/%d (%s)",
			time.Since(start).Truncate(time.Second), ready, len(refs), strings.Join(states, ", "))

		if ready == len(refs) {
			t.Logf("port reboot complete in %v", time.Since(start).Truncate(time.Second))
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port reboot: timed out after %v waiting for the ports to come back (%d/%d ready: %s)",
				*portRebootTimeout, ready, len(refs), strings.Join(states, ", "))
		}
		time.Sleep(10 * time.Second)
	}
}

// logCardHealth samples the per-port memory and PCPU status of the ports under
// test, plus the chassis CPU and memory.
//
// IxOS exposes no per-port CPU utilisation figure over its REST API -- only the
// PCPU's readiness state -- so the chassis-wide CPU counter is logged as the
// closest available proxy. Failures here are logged and never fail the run:
// this is diagnostic data, and a chassis still on a default password refuses to
// issue a REST session at all.
func logCardHealth(t *testing.T, inv *chassisInventory, when string) {
	t.Helper()
	if inv == nil {
		return
	}
	refs := make([]portRef, 0, len(inv.Ports))
	seen := map[string]bool{}
	for _, p := range inv.Ports {
		refs = append(refs, p.Ref)
		if seen[p.Ref.Chassis] {
			continue
		}
		seen[p.Ref.Chassis] = true
		perf, err := fetchChassisPerf(p.Ref.Chassis, *chassisUser, *chassisPass, *chassisTimeout)
		if err != nil {
			t.Logf("[%s] chassis %s CPU/memory unavailable: %v", when, p.Ref.Chassis, err)
			continue
		}
		t.Logf("[%s] chassis %s: %s", when, p.Ref.Chassis, perf)
	}

	health, err := fetchPortHealthFor(*chassisUser, *chassisPass, refs, *chassisTimeout)
	if err != nil {
		t.Logf("[%s] port memory / PCPU status unavailable: %v", when, err)
		return
	}
	for _, r := range refs {
		h, ok := health[r.String()]
		if !ok {
			t.Logf("[%s] port %s: no health reported", when, r)
			continue
		}
		t.Logf("[%s] port %s: memory %d MB, PCPU %s, link %s, speed %d Mbps, owner %q",
			when, r, h.MemoryMB, h.PcpuStatus, h.LinkState, h.SpeedMbps, h.Owner)
	}
}

// buildScaleConfig creates the b2b OTG config: `sessions` BGPv6 peers on each
// port, every peer advertising `routes` /128 prefixes, plus a capped set of flows
// running over the advertised route ranges.
func buildScaleConfig(t *testing.T, sessions, routes uint32) *scaleConfig {
	t.Helper()
	config := gosnappi.NewConfig()
	config.Ports().Add().SetName("port1")
	config.Ports().Add().SetName("port2")

	// Port L1 MTU, raised so the tagged frames fit: the device MTU is 1500 and each
	// VLAN tag adds 4 bytes on the wire.
	config.Layer1().Add().SetName("jumboframe").
		SetPortNames([]string{"port1", "port2"}).
		SetMtu(uint32(*l1MTU))

	sc := &scaleConfig{config: config}

	// Every peer is iBGP in the same AS.
	as := uint32(*asNum)

	// port1 side takes ::1 of each session subnet, port2 side takes ::2.
	for i := uint32(1); i <= sessions; i++ {
		peer := configureSide(t, config, "port1", "p1", p1MACStart, p1RouteStart, 1, 2, i, routes, as)
		sc.peers = append(sc.peers, peer)
	}
	// port2 side.
	for i := uint32(1); i <= sessions; i++ {
		peer := configureSide(t, config, "port2", "p2", p2MACStart, p2RouteStart, 2, 1, i, routes, as)
		sc.peers = append(sc.peers, peer)
	}

	// Data-plane sanity check: one flow per session pair, over the route ranges
	// advertised by the paired peers. ixia-c allows a single tx device per flow,
	// so the flow count cannot be collapsed; cap it instead.
	if *runTraffic && routes > 0 {
		numFlows := uint32(*maxFlows)
		if sessions < numFlows {
			numFlows = sessions
		}
		for i := uint32(1); i <= numFlows; i++ {
			txRR := routeRangeName("p1", i)
			rxRR := routeRangeName("p2", i)
			name := "flow-" + txRR + "-to-" + rxRR
			flow := config.Flows().Add().SetName(name)
			flow.Metrics().SetEnable(true)
			flow.TxRx().Device().SetTxNames([]string{txRR}).SetRxNames([]string{rxRR})
			flow.Duration().FixedPackets().SetPackets(uint32(*flowPackets))
			flow.Rate().SetPps(uint64(*flowPps))
			flow.Size().SetFixed(uint32(*flowSize))

			// Dst MAC is set explicitly to the paired port2 device's MAC rather than
			// left on "auto": auto makes `start flows` fail unless ixia-c has a
			// neighbor entry for the tx device's gateway, and this config knows the
			// answer already.
			eth := flow.Packet().Add().Ethernet()
			eth.Src().SetValue(macFor(t, p1MACStart, i))
			eth.Dst().SetValue(macFor(t, p2MACStart, i))

			// Tagged devices need the same tags on the transmitted frames, outer
			// tag first.
			if *vlanTagging {
				inner, outer := vlanIDs(i)
				if *qinqTagging {
					flow.Packet().Add().Vlan().Id().SetValue(outer)
				}
				flow.Packet().Add().Vlan().Id().SetValue(inner)
			}

			v6 := flow.Packet().Add().Ipv6()
			v6.Src().Increment().SetStart(routeStartFor(p1RouteStart, i, routes)).SetCount(routes)
			v6.Dst().Increment().SetStart(routeStartFor(p2RouteStart, i, routes)).SetCount(routes)

			sc.flowNames = append(sc.flowNames, name)
		}
	}
	return sc
}

// configureSide adds one device (ethernet + vlans + ipv6 + BGPv6 peer + route
// range) for session index i on the given port, and returns the BGP peer name.
// host is the device's host id inside the session subnet and gwHost is its
// gateway's (::1 on port1, ::2 on port2).
func configureSide(t *testing.T, config gosnappi.Config, portName, sidePfx, macStart, routeStart string, host, gwHost byte, i, routes, as uint32) string {
	t.Helper()
	idx := strconv.Itoa(int(i))
	devName := sidePfx + "dev" + idx
	ipName := devName + ".ipv6"
	peerName := sidePfx + "peer" + idx

	devIP := sessionIP(t, i, host)
	gwIP := sessionIP(t, i, gwHost)

	dev := config.Devices().Add().SetName(devName)
	eth := dev.Ethernets().Add().SetName(devName + ".eth").SetMac(macFor(t, macStart, i)).SetMtu(ethMTU)
	eth.Connection().SetPortName(portName)

	// The tag pair depends only on the session index, so the paired port1 and
	// port2 devices land in the same broadcast domain. Outer (QinQ) tag is added
	// first, inner dot1q tag second.
	if *vlanTagging {
		inner, outer := vlanIDs(i)
		if *qinqTagging {
			eth.Vlans().Add().SetName(devName + ".qinq").SetId(outer)
		}
		eth.Vlans().Add().SetName(devName + ".vlan").SetId(inner)
	}

	eth.Ipv6Addresses().Add().SetName(ipName).
		SetAddress(devIP.String()).
		SetGateway(gwIP.String()).
		SetPrefix(uint32(*ipPrefix))

	bgp := dev.Bgp().SetRouterId(routerIDFor(t, sidePfx, i))
	bgpIf := bgp.Ipv6Interfaces().Add().SetIpv6Name(ipName)
	peer := bgpIf.Peers().Add().
		SetAsNumber(as).
		SetAsType(gosnappi.BgpV6PeerAsType.IBGP).
		SetPeerAddress(gwIP.String()).
		SetName(peerName)
	peer.LearnedInformationFilter().SetUnicastIpv6Prefix(true)

	// Optional non-default TCP ports, mirrored between the two sides.
	if *listenPort > 0 && *neighborPort > 0 {
		lp, np := uint32(*listenPort), uint32(*neighborPort)
		if sidePfx != "p1" {
			lp, np = np, lp
		}
		adv := peer.Advanced()
		adv.SetListenPort(lp)
		adv.SetNeighborPort(np)
	}

	if routes > 0 {
		rr := peer.V6Routes().Add().
			SetName(routeRangeName(sidePfx, i)).
			SetNextHopIpv6Address(devIP.String()).
			SetNextHopAddressType(gosnappi.BgpV6RouteRangeNextHopAddressType.IPV6).
			SetNextHopMode(gosnappi.BgpV6RouteRangeNextHopMode.MANUAL)
		rr.Addresses().Add().
			SetAddress(routeStartFor(routeStart, i, routes)).
			SetPrefix(routePrefix).
			SetCount(routes).
			SetStep(1)
	}
	return peerName
}

func routeRangeName(sidePfx string, i uint32) string {
	return sidePfx + "rr" + strconv.Itoa(int(i))
}

func routeStartFor(base string, i, routes uint32) string {
	return nextIPv6(net.ParseIP(base), uint((i-1)*routes)).String()
}

// routerIDFor returns the router ID for session index i on the given side: the
// session index added to the side's IPv4 base, so the router ID lines up with the
// device's subnet (2001:db8:0:i::/64 -> 10.1.0.i on port1). The OTG model validates
// router_id as an IPv4 address, which is why the v6 interface address cannot be
// used verbatim.
func routerIDFor(t *testing.T, sidePfx string, i uint32) string {
	t.Helper()
	base := *p1RouterID
	if sidePfx == "p2" {
		base = *p2RouterID
	}
	ip := net.ParseIP(base)
	if ip == nil || ip.To4() == nil {
		t.Fatalf("router ID base %q is not a valid IPv4 address", base)
	}
	return nextIP4(ip, uint(i)).String()
}

// sessionIP returns host address `host` inside session i's own /64: the base address
// with its 4th hextet set to the session index, e.g. session 1 -> 2001:db8:0:1::/64
// holding ::1 (port1) and ::2 (port2). 65535 sessions fit.
func sessionIP(t *testing.T, i uint32, host byte) net.IP {
	t.Helper()
	base := net.ParseIP(*subnetBase)
	if base == nil || base.To4() != nil {
		t.Fatalf("subnet base %q is not a valid IPv6 address", *subnetBase)
	}
	if i > 0xFFFF {
		t.Fatalf("session index %d does not fit the 16-bit subnet id", i)
	}
	out := make(net.IP, net.IPv6len)
	copy(out, base.To16())
	out[6], out[7] = byte(i>>8), byte(i)
	out[15] = host
	return out
}

// nextIP4 returns the IPv4 address ip incremented by inc.
func nextIP4(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	return net.IPv4(byte((v>>24)&0xFF), byte((v>>16)&0xFF), byte((v>>8)&0xFF), byte(v&0xFF))
}

// vlanIDs maps a 1-based session index onto its (inner dot1q, outer QinQ) tag pair,
// the same scheme as scale.GenerateVlanIds: the inner id cycles through 1..4095 and
// the outer id advances once per full cycle, so both stay inside the 0..4095 range
// the OTG model allows while remaining unique up to 4095*4095 sessions.
func vlanIDs(i uint32) (inner, outer uint32) {
	if i == 0 {
		return 0, 1
	}
	band := (i - 1) / 4095
	return i - band*4095, band + 1
}

// awaitSessionsEstablished polls OTG gNMI until every configured peer reports
// ESTABLISHED, backing off less aggressively as sessions come up.
func awaitSessionsEstablished(t *testing.T, otgDev *otg.OTG, peers []string, timeout time.Duration) {
	t.Helper()
	want := len(peers)
	deadline := time.Now().Add(timeout)
	base := basePollInterval(want)
	start := time.Now()

	for {
		stStart := time.Now()
		st := sessionStates(t, otgDev, peers)
		stTook := apiTime.track(apiGetBGPStates, stStart)

		ctStart := time.Now()
		c := bgpCounters(t, otgDev, peers)
		ctTook := apiTime.track(apiGetBGPCounters, ctStart)

		t.Logf("[t+%-6v] BGPv6 sessions ESTABLISHED: %d/%d | GetMetrics: state %v, counters %v | states: %s%s",
			time.Since(start).Truncate(time.Second), st.up, want,
			stTook.Round(time.Millisecond), ctTook.Round(time.Millisecond),
			st.histogram(), st.downList())
		t.Log(c.String(uint64(want), 0))
		if st.up == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v: %d/%d BGPv6 sessions ESTABLISHED (states: %s)", timeout, st.up, want, st.histogram())
		}
		time.Sleep(adaptivePollInterval(base, st.up, want))
	}
}

// sessionStateSummary is the distribution of session states over all peers.
type sessionStateSummary struct {
	up       int
	reported int
	byState  map[string]int
	down     []string // capped sample of "peer=STATE" for peers not ESTABLISHED
}

func (s sessionStateSummary) histogram() string {
	if s.reported == 0 {
		return "no peer reported a session state"
	}
	keys := make([]string, 0, len(s.byState))
	for k := range s.byState {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, s.byState[k]))
	}
	return strings.Join(parts, " ")
}

func (s sessionStateSummary) downList() string {
	if len(s.down) == 0 {
		return ""
	}
	return "\n\tnot ESTABLISHED (sample): " + strings.Join(s.down, ", ")
}

// sessionStates reads the session state of every configured peer.
func sessionStates(t *testing.T, otgDev *otg.OTG, peers []string) sessionStateSummary {
	t.Helper()
	const maxDownLogged = 10
	s := sessionStateSummary{byState: map[string]int{}}

	record := func(name string, st otgtelemetry.E_BgpPeer_SessionState) {
		s.reported++
		s.byState[st.String()]++
		if st == otgtelemetry.BgpPeer_SessionState_ESTABLISHED {
			s.up++
		} else if len(s.down) < maxDownLogged {
			s.down = append(s.down, fmt.Sprintf("%s=%s", name, st.String()))
		}
	}

	if *useWildcard {
		vals := gnmi.LookupAll(t, otgDev, gnmi.OTG().BgpPeerAny().SessionState().State())
		if len(vals) > 0 {
			for _, v := range vals {
				if st, ok := v.Val(); ok {
					record(peerNameFromPath(v), st)
				}
			}
			return s
		}
		t.Logf("wildcard BgpPeerAny() session-state query returned no peers; falling back to per-peer queries")
		*useWildcard = false
	}

	for _, p := range peers {
		if st, ok := gnmi.Lookup(t, otgDev, gnmi.OTG().BgpPeer(p).SessionState().State()).Val(); ok {
			record(p, st)
		}
	}
	return s
}

// logPortAndArpState logs port link state and, for a sample of devices, whether
// the BGP peer address (== the gateway) resolved via IPv6 neighbor discovery. A
// session stuck below ESTABLISHED with an unresolved gateway is an
// addressing/link problem, not BGP.
func logPortAndArpState(t *testing.T, otgDev *otg.OTG, config gosnappi.Config, sample int) {
	t.Helper()
	start := time.Now()
	defer func() {
		t.Logf("GetMetrics: port / neighbor state took %v",
			apiTime.track(apiGetPortState, start).Round(time.Millisecond))
	}()
	for _, p := range config.Ports().Items() {
		// Note: ixia-c reports link state as DOWN for Ixia HW ports even when the
		// port is up and passing traffic, so treat this as informational only.
		if v, ok := gnmi.Lookup(t, otgDev, gnmi.OTG().Port(p.Name()).Link().State()).Val(); ok {
			t.Logf("port %s link (as reported by OTG gNMI): %s", p.Name(), v.String())
		} else {
			t.Logf("port %s link: no state reported", p.Name())
		}
	}
	n := 0
	for _, d := range config.Devices().Items() {
		if n >= sample {
			return
		}
		for _, eth := range d.Ethernets().Items() {
			for _, ip := range eth.Ipv6Addresses().Items() {
				gw := ip.Gateway()
				mac, ok := gnmi.Lookup(t, otgDev, gnmi.OTG().Interface(eth.Name()).Ipv6Neighbor(gw).LinkLayerAddress().State()).Val()
				if ok {
					t.Logf("device %s: %s -> gateway %s resolved to %s", d.Name(), ip.Address(), gw, mac)
				} else {
					t.Logf("device %s: %s -> gateway %s NOT resolved (no neighbor entry)", d.Name(), ip.Address(), gw)
				}
			}
		}
		n++
	}
}

// peerNameFromPath pulls the peer "name" key out of a wildcard query result path.
func peerNameFromPath[T any](v *ygnmi.Value[T]) string {
	if v == nil || v.Path == nil {
		return "?"
	}
	for _, e := range v.Path.GetElem() {
		if n, ok := e.GetKey()["name"]; ok {
			return n
		}
	}
	return "?"
}

// verifyBGPCounters polls the aggregated BGP peer counters until the advertised /
// received route counts match expectation, and fails on any session flap.
func verifyBGPCounters(t *testing.T, otgDev *otg.OTG, peers []string, sessions, routes uint32, timeout time.Duration) {
	t.Helper()
	// Both ports advertise a route range, so every peer sends and receives
	// `routes` routes.
	wantRoutes := uint64(2*sessions) * uint64(routes)
	deadline := time.Now().Add(timeout)
	base := basePollInterval(len(peers))

	for {
		ctStart := time.Now()
		c := bgpCounters(t, otgDev, peers)
		t.Logf("GetMetrics: BGP peer counters for %d peers took %v",
			len(peers), apiTime.track(apiGetBGPCounters, ctStart).Round(time.Millisecond))
		t.Log(c.String(uint64(len(peers)), wantRoutes))

		ok := c.flaps == 0 && c.inRoutes == wantRoutes && c.outRoutes == wantRoutes &&
			c.inRouteWithdraw == 0 && c.outRouteWithdraw == 0
		if ok {
			return
		}
		if c.flaps > 0 {
			t.Errorf("BGP session flaps: got %d, want 0", c.flaps)
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("timed out after %v waiting for BGP route counters: in-routes got %d want %d, out-routes got %d want %d, withdraws in/out %d/%d want 0/0",
				timeout, c.inRoutes, wantRoutes, c.outRoutes, wantRoutes, c.inRouteWithdraw, c.outRouteWithdraw)
			return
		}
		time.Sleep(base)
	}
}

type bgpCounterSum struct {
	peers                               uint64
	flaps                               uint64
	inOpens, outOpens                   uint64
	inKeepalives, outKeepalives         uint64
	inUpdates, outUpdates               uint64
	inNotifications, outNotifications   uint64
	inRoutes, outRoutes                 uint64
	inRouteWithdraw, outRouteWithdraw   uint64
	inEndOfRib                          uint64
	peersWithOpens, peersWithKeepalives uint64
}

// String renders the aggregated counters. wantRoutes == 0 means "route counts are
// not being checked yet" (used while sessions are still coming up).
func (c bgpCounterSum) String(wantPeers, wantRoutes uint64) string {
	border := strings.Repeat("-", 78)
	routeExp := "(Expected : n/a yet)"
	if wantRoutes > 0 {
		routeExp = fmt.Sprintf("(Expected : %d)", wantRoutes)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\t\tAggregated BGPv6 Metrics (OTG gNMI)\n%s\n", border)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v\n", "Counter", "Sent (out)", "Received (in)")
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v\n", "Opens", c.outOpens, c.inOpens)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v\n", "Keepalives", c.outKeepalives, c.inKeepalives)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v\n", "Updates", c.outUpdates, c.inUpdates)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v  (Expected : 0/0)\n", "Notifications", c.outNotifications, c.inNotifications)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v  %s\n", "Routes", c.outRoutes, c.inRoutes, routeExp)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v  (Expected : 0/0)\n", "Route Withdraws", c.outRouteWithdraw, c.inRouteWithdraw)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v\n", "End-Of-RIB", "-", c.inEndOfRib)
	fmt.Fprintf(&b, "%s\n", border)
	fmt.Fprintf(&b, "\t\t%-26v %-14v (Expected : %d)\n", "Peers Reporting Counters", c.peers, wantPeers)
	fmt.Fprintf(&b, "\t\t%-26v %-14v (Expected : %d)\n", "Peers That Sent An Open", c.peersWithOpens, wantPeers)
	fmt.Fprintf(&b, "\t\t%-26v %-14v (Expected : %d)\n", "Peers Exchanging Keepalive", c.peersWithKeepalives, wantPeers)
	fmt.Fprintf(&b, "\t\t%-26v %-14v (Expected : 0)\n", "Flap Count", c.flaps)
	fmt.Fprintf(&b, "%s\n", border)
	return b.String()
}

func (c *bgpCounterSum) add(v *otgtelemetry.BgpPeer_Counters) {
	if v == nil {
		return
	}
	c.peers++
	c.flaps += v.GetFlaps()
	c.inOpens += v.GetInOpens()
	c.outOpens += v.GetOutOpens()
	c.inKeepalives += v.GetInKeepalives()
	c.outKeepalives += v.GetOutKeepalives()
	c.inUpdates += v.GetInUpdates()
	c.outUpdates += v.GetOutUpdates()
	c.inNotifications += v.GetInNotifications()
	c.outNotifications += v.GetOutNotifications()
	c.inRoutes += v.GetInRoutes()
	c.outRoutes += v.GetOutRoutes()
	c.inRouteWithdraw += v.GetInRouteWithdraw()
	c.outRouteWithdraw += v.GetOutRouteWithdraw()
	c.inEndOfRib += v.GetInEndOfRib()
	if v.GetOutOpens() > 0 {
		c.peersWithOpens++
	}
	if v.GetInKeepalives() > 0 || v.GetOutKeepalives() > 0 {
		c.peersWithKeepalives++
	}
}

func bgpCounters(t *testing.T, otgDev *otg.OTG, peers []string) bgpCounterSum {
	t.Helper()
	var sum bgpCounterSum

	if *useWildcard {
		vals := gnmi.LookupAll(t, otgDev, gnmi.OTG().BgpPeerAny().Counters().State())
		if len(vals) > 0 {
			for _, v := range vals {
				if c, ok := v.Val(); ok {
					sum.add(c)
				}
			}
			return sum
		}
		t.Logf("wildcard BgpPeerAny() counters query returned no peers; falling back to per-peer queries")
		*useWildcard = false
	}

	for _, p := range peers {
		if c, ok := gnmi.Lookup(t, otgDev, gnmi.OTG().BgpPeer(p).Counters().State()).Val(); ok {
			sum.add(c)
		}
	}
	return sum
}

// sendTraffic starts the fixed-packet flows and waits until every flow has
// actually finished transmitting before stopping traffic. Flows are started in
// batches by ixia-c, so at higher flow counts the last flows begin transmitting
// well after StartTraffic returns; reading counters on a fixed sleep would show
// flows with tx == 0 that had simply not run yet.
func sendTraffic(t *testing.T, otgDev *otg.OTG, flowNames []string) {
	t.Helper()
	wantPkts := uint64(*flowPackets)
	txTime := time.Duration(float64(*flowPackets) / float64(*flowPps) * float64(time.Second))
	t.Logf("Starting traffic on %d flows (%d packets @ %d pps => %v of transmit per flow)",
		len(flowNames), wantPkts, *flowPps, txTime)
	apiTime.call(t, apiStartTraffic, func() { otgDev.StartTraffic(t) })

	awaitFlowsStopped(t, otgDev, flowNames, wantPkts, *trafficTimeout)

	t.Logf("Stopping traffic")
	apiTime.call(t, apiStopTraffic, func() { otgDev.StopTraffic(t) })
}

// awaitFlowsStopped polls until every flow reports transmit == false (stopped)
// and has sent its full packet count. Flow-name wildcards are not reliably served
// by the ixia-c gNMI server, so each flow is queried by name; flows that are
// already done are dropped from the polled set so later polls get cheaper.
func awaitFlowsStopped(t *testing.T, otgDev *otg.OTG, flowNames []string, wantPkts uint64, timeout time.Duration) {
	t.Helper()
	pending := make(map[string]bool, len(flowNames))
	for _, n := range flowNames {
		pending[n] = true
	}
	total := len(flowNames)
	deadline := time.Now().Add(timeout)
	start := time.Now()

	for len(pending) > 0 {
		var txSoFar uint64
		stillRunning, shortTx := 0, 0
		polled := len(pending)
		fetchStart := time.Now()
		for name := range pending {
			m, ok := gnmi.Lookup(t, otgDev, gnmi.OTG().Flow(name).State()).Val()
			if !ok {
				continue
			}
			tx := m.GetCounters().GetOutPkts()
			txSoFar += tx
			transmitting := m.GetTransmit()
			if transmitting {
				stillRunning++
			}
			if tx < wantPkts {
				shortTx++
			}
			if !transmitting && tx >= wantPkts {
				delete(pending, name)
			}
		}
		fetchTook := apiTime.track(apiGetFlowMetrics, fetchStart)
		t.Logf("[t+%-6v] flows finished transmitting: %d/%d (still transmitting: %d, below %d packets: %d, tx on pending flows: %d) | GetMetrics: %d flows in %v",
			time.Since(start).Truncate(time.Second), total-len(pending), total, stillRunning, wantPkts, shortTx, txSoFar,
			polled, fetchTook.Round(time.Millisecond))
		if len(pending) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("timed out after %v waiting for flows to finish transmitting: %d/%d still not done",
				timeout, len(pending), total)
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// verifyTraffic checks, per flow, that the full packet count was transmitted and
// that rx matches tx. Concrete per-flow queries are used because flow-name
// wildcards are not reliably served by the ixia-c gNMI server.
func verifyTraffic(t *testing.T, otgDev *otg.OTG, flowNames []string) {
	t.Helper()
	wantPkts := uint64(*flowPackets)
	var totalTx, totalRx uint64
	shortTx, lossy := 0, 0
	fetchStart := time.Now()
	for _, name := range flowNames {
		m := gnmi.Get(t, otgDev, gnmi.OTG().Flow(name).State())
		tx := m.GetCounters().GetOutPkts()
		rx := m.GetCounters().GetInPkts()
		totalTx += tx
		totalRx += rx
		if tx < wantPkts {
			t.Errorf("flow %s transmitted %d packets, want %d", name, tx, wantPkts)
			shortTx++
		}
		if tx == 0 {
			continue
		}
		lost := int64(tx) - int64(rx)
		lossPct := float64(lost) * 100 / float64(tx)
		if lost > tolerancePkts && lossPct > tolerancePct {
			t.Errorf("flow %s loss: tx %d, rx %d, loss %.2f%%, want <= %.2f%%", name, tx, rx, lossPct, tolerancePct)
			lossy++
		}
	}
	fetchTook := apiTime.track(apiGetFlowMetrics, fetchStart)
	wantTotal := uint64(len(flowNames)) * wantPkts
	lossPct := 0.0
	if totalTx > 0 {
		lossPct = float64(int64(totalTx)-int64(totalRx)) * 100 / float64(totalTx)
	}
	t.Logf("Traffic summary over %d flows: tx %d (expected %d), rx %d, loss %.2f%%, flows short on tx %d, lossy flows %d | GetMetrics: %d flows in %v",
		len(flowNames), totalTx, wantTotal, totalRx, lossPct, shortTx, lossy,
		len(flowNames), fetchTook.Round(time.Millisecond))
	if totalTx != totalRx {
		t.Errorf("aggregate tx != rx: tx %d, rx %d", totalTx, totalRx)
	}
}

// basePollInterval scales the telemetry poll interval with the number of peers so
// that polling does not dominate the gNMI server at high scale.
func basePollInterval(peers int) time.Duration {
	switch {
	case peers <= 100:
		return 2 * time.Second
	case peers <= 1000:
		return 5 * time.Second
	case peers <= 10000:
		return 15 * time.Second
	default:
		return 30 * time.Second
	}
}

// adaptivePollInterval shortens the interval as sessions come up, so that the
// last few sessions are detected quickly.
func adaptivePollInterval(base time.Duration, up, want int) time.Duration {
	if want == 0 {
		return base
	}
	switch ratio := float64(up) / float64(want); {
	case ratio >= 0.99:
		return base / 8
	case ratio >= 0.9:
		return base / 4
	case ratio >= 0.5:
		return base / 2
	default:
		return base
	}
}

// macFor returns macStart incremented by (i-1).
func macFor(t *testing.T, macStart string, i uint32) string {
	t.Helper()
	hw, err := net.ParseMAC(macStart)
	if err != nil {
		t.Fatalf("cannot parse MAC %s: %v", macStart, err)
	}
	v := uint64(0)
	for _, b := range hw {
		v = v<<8 | uint64(b)
	}
	v += uint64(i - 1)
	for p := 5; p >= 0; p-- {
		hw[p] = byte(v & 0xFF)
		v >>= 8
	}
	return hw.String()
}

// nextIPv6 returns ip incremented by inc, carrying over the low 32 bits of the
// address. This keeps the increment simple while comfortably covering the
// address ranges this test needs (tens of thousands of sessions).
func nextIPv6(ip net.IP, inc uint) net.IP {
	i := ip.To16()
	out := make(net.IP, net.IPv6len)
	copy(out, i)
	v := uint(i[12])<<24 + uint(i[13])<<16 + uint(i[14])<<8 + uint(i[15])
	v += inc
	out[12] = byte((v >> 24) & 0xFF)
	out[13] = byte((v >> 16) & 0xFF)
	out[14] = byte((v >> 8) & 0xFF)
	out[15] = byte(v & 0xFF)
	return out
}

// ---------------------------------------------------------------------------
// OTG API call timing
//
// Every OTG API call the test makes is timed, so a scale run shows where its
// wall clock actually went. That matters here more than it would in a
// functional test: at high session counts SetConfig and StartProtocols
// dominate the run, and how long a GetMetrics fetch takes is what decides how
// often a scale can be observed at all.
//
// One-shot calls are highlighted with a ">>> OTG API" line as they happen. The
// fetches inside the poll loops are timed per poll and appended to the poll's
// own log line, then aggregated (count / total / avg / min / max) into the
// per-iteration table.
//
// The recorder is a package-level value rather than a parameter threaded
// through every helper: this test is deliberately one self-contained file, and
// a single Go test function runs serially, so there is nothing to race.
// ---------------------------------------------------------------------------

// Labels for the timed calls. Where the ondatra/gosnappi name differs from the
// OTG API it drives, both are given.
const (
	apiSetConfig      = "PushConfig [SetConfig]"
	apiStartProtocols = "StartProtocols"
	apiStopProtocols  = "StopProtocols"
	apiStartTraffic   = "StartTraffic [SetTransmitState:start]"
	apiStopTraffic    = "StopTraffic [SetTransmitState:stop]"
	apiGetBGPStates   = "GetMetrics: BGP session state"
	apiGetBGPCounters = "GetMetrics: BGP peer counters"
	apiGetFlowMetrics = "GetMetrics: flow metrics"
	apiGetPortState   = "GetMetrics: port / neighbor state"
)

// apiCallStat aggregates every duration recorded under one label.
type apiCallStat struct {
	calls    int
	total    time.Duration
	min, max time.Duration
}

func (s apiCallStat) avg() time.Duration {
	if s.calls == 0 {
		return 0
	}
	return s.total / time.Duration(s.calls)
}

// apiTimings records OTG API call durations for one iteration, in the order the
// labels were first seen.
type apiTimings struct {
	order []string
	stat  map[string]*apiCallStat
}

var apiTime = newAPITimings()

func newAPITimings() *apiTimings {
	return &apiTimings{stat: map[string]*apiCallStat{}}
}

// Reset drops everything recorded so far, so each iteration reports its own
// timings rather than the run's running total.
func (a *apiTimings) Reset() {
	a.order = nil
	a.stat = map[string]*apiCallStat{}
}

// record files one duration under label and returns it unchanged.
func (a *apiTimings) record(label string, d time.Duration) time.Duration {
	s, ok := a.stat[label]
	if !ok {
		s = &apiCallStat{min: d, max: d}
		a.stat[label] = s
		a.order = append(a.order, label)
	}
	s.calls++
	s.total += d
	if d < s.min {
		s.min = d
	}
	if d > s.max {
		s.max = d
	}
	return d
}

// call runs a one-shot OTG API call, records how long it took and highlights it
// in the log. Use track for calls made once per poll, which would flood the log
// at scale.
func (a *apiTimings) call(t *testing.T, label string, fn func()) time.Duration {
	t.Helper()
	start := time.Now()
	fn()
	d := a.record(label, time.Since(start))
	t.Logf(">>> OTG API | %-38s %14v", label, d.Round(time.Millisecond))
	return d
}

// track records a duration the caller measured itself, without logging it, and
// returns it so the caller can fold it into its own log line.
func (a *apiTimings) track(label string, start time.Time) time.Duration {
	return a.record(label, time.Since(start))
}

// String renders the recorded timings as a log block. when labels the scope the
// numbers cover, e.g. "iteration 1/3, 1000 sessions/port".
func (a *apiTimings) String(when string) string {
	border := strings.Repeat("-", 100)
	var b strings.Builder
	fmt.Fprintf(&b, "\n\t\tOTG API call timings (%s)\n%s\n", when, border)
	fmt.Fprintf(&b, "\t\t%-38s %6s %14s %14s %14s %14s\n",
		"API call", "calls", "total", "avg", "min", "max")
	if len(a.order) == 0 {
		fmt.Fprintf(&b, "\t\tno API calls recorded\n%s\n", border)
		return b.String()
	}
	var grand time.Duration
	for _, label := range a.order {
		s := a.stat[label]
		grand += s.total
		fmt.Fprintf(&b, "\t\t%-38s %6d %14v %14v %14v %14v\n", label, s.calls,
			s.total.Round(time.Millisecond), s.avg().Round(time.Millisecond),
			s.min.Round(time.Millisecond), s.max.Round(time.Millisecond))
	}
	fmt.Fprintf(&b, "%s\n", border)
	fmt.Fprintf(&b, "\t\t%-38s %6s %14v\n", "total time in OTG API calls", "", grand.Round(time.Millisecond))
	fmt.Fprintf(&b, "%s\n", border)
	return b.String()
}

// ---------------------------------------------------------------------------
// Ixia chassis / card discovery
//
// Everything below resolves the ports named in the binding to the physical
// chassis, card and resource group they live on, derives the session and flow
// capacity that card is rated for, and reads its health counters. It is kept
// in this file so the test stays self-contained and can be handed out on its
// own.
//
// Two sources are used, because neither alone is sufficient:
//
//   - The IxOS CLI over SSH ("show topology") is the only place the resource
//     group layout is exposed, and that layout -- how many ports a group is
//     broken out into -- is what selects the row of the performance matrix.
//     REST reports a port speed but not its group, and speed alone is
//     ambiguous: a 2-port group running 100G NRZ is rated the same as one
//     running 400G PAM4.
//   - The IxOS REST API (/chassis/api/v2/ixos/...) carries the per-port memory
//     and PCPU status, and the chassis CPU / memory perf counters.
//
// REST is best effort. A chassis still on a default password refuses to issue
// an API session at all ("resetWeakPassword"), and on those the SSH data alone
// still yields the card type, the group mode and therefore the limits.
// ---------------------------------------------------------------------------

// Rated per-port protocol-session capacity, from the Athena performance matrix
// ("Per Resource Group (#ports * speedMode)").
//
// AresONE: a resource group is rated for aresOneGroupV4 / aresOneGroupV6
// sessions in total, split evenly over however many ports the group is broken
// out into. That is why the matrix columns halve as the port count doubles:
// 1x800G 36556, 2x400G 18278, 4x200G 9139, 8x100G 4570, 16x50G 2285 (and the
// same progression for v6 from 26982).
const (
	aresOneGroupV4 = 36556
	aresOneGroupV6 = 26982

	// Novus 10G/1GE/100M cards in normal (non-aggregated) mode.
	//
	// NOTE: the performance matrix screenshot shows 35686 / 31334 for this row.
	// These values are per an explicit instruction to rate the Novus 10G card at
	// the same 36556 / 26982 as an unsplit AresONE group. Change these two
	// constants back to 35686 / 31334 to follow the published matrix.
	novusNormalV4 = 36556
	novusNormalV6 = 26982

	// Novus 10G/1GE/100M cards in aggregated mode. NOVUS-NP10/1GE16DP does not
	// support aggregated mode and is excluded from this row in the matrix.
	novusAggregatedV4 = 60928
	novusAggregatedV6 = 60928

	// NOVUS10/1GE32S.
	novus32SV4 = 17843
	novus32SV6 = 15667

	// SERT 100G (100GE-QSFP28, 25G = 4*10G).
	sert100GV4 = 4461
	sert100GV6 = 3373

	// Rated concurrent-flow capacity per port. A zero MaxFlows on a card means
	// "not rated here", and the -scale_max_flows value is then used as given.
	aresOneMaxFlows = 256
	// The whole NOVUS10/1GE/100M family, including NOVUS10/1GE32S.
	novus10GMaxFlows = 512
)

// Row names of the performance matrix. These are the keys of the "rows" object
// in card_limits.json.
const (
	rowAresOne         = "aresone"
	rowNovusNormal     = "novus_normal"
	rowNovusAggregated = "novus_aggregated"
	rowNovus32S        = "novus_1ge32s"
	rowSert100G        = "sert_100g"
)

// ---------------------------------------------------------------------------
// The card limits table
//
// The constants above are the built-in matrix, and they are what a copy of this
// file enforces on its own. A card_limits.json next to the test, or one
// directory up (so a parent folder can hold one table shared by the v4 and v6
// tests), overrides them -- a corrected rating, or a row for a card the matrix
// does not cover -- without editing Go. -scale_limits_file names one explicitly.
//
// Two rules keep the file from quietly changing what a run enforced:
//
//   - Which source is in force is logged at discovery, along with every row the
//     file changed. A limit is only meaningful if the log says where its number
//     came from, and with an overridable table that is no longer implied by the
//     test's version alone.
//   - A file that exists but cannot be read or parsed is FATAL, not ignored.
//     Someone put it there deliberately; falling back to the built-ins would
//     enforce a different number than the one they wrote down.
//
// Fields absent from a row keep their built-in value, so a file can correct one
// number without restating the row. That is why the JSON form uses pointers:
// with plain values an omitted "bgpv4" would be indistinguishable from a
// deliberate 0, which means "unrated" and would silently disable the check.
// ---------------------------------------------------------------------------

// limitsFileName is searched for next to the test, then one directory up.
const limitsFileName = "card_limits.json"

// limitRow is one row of the performance matrix.
type limitRow struct {
	BGPv4    uint32
	BGPv6    uint32
	MaxFlows uint32
}

// limitRowJSON is the on-disk form of a row. Every field is optional; see the
// note on pointers above.
type limitRowJSON struct {
	BGPv4    *uint32 `json:"bgpv4"`
	BGPv6    *uint32 `json:"bgpv6"`
	MaxFlows *uint32 `json:"max_flows"`
}

// cardRule rates a card the built-in matrix has no row for. Match is compared
// case-insensitively as a substring of the card type reported by the chassis,
// and the first matching rule wins over every built-in rule.
type cardRule struct {
	Match    string `json:"match"`
	BGPv4    uint32 `json:"bgpv4"`
	BGPv6    uint32 `json:"bgpv6"`
	MaxFlows uint32 `json:"max_flows"`
	// PerGroup marks BGPv4/BGPv6 as a whole-resource-group total to be split
	// evenly over the ports the group is broken out into, the way AresONE is
	// rated. Leave it false for a flat per-port figure.
	PerGroup bool `json:"per_group"`
	// Source is what the run log will cite as the reason for the limit.
	Source string `json:"source"`
}

// limitsTable is the matrix actually in force for a run.
type limitsTable struct {
	Rows  map[string]limitRow
	Cards []cardRule
	// Source describes where the table came from, for the run log.
	Source string
}

// limitsFileFormat is the on-disk form of limitsTable.
type limitsFileFormat struct {
	Rows  map[string]limitRowJSON `json:"rows"`
	Cards []cardRule              `json:"cards"`
}

// builtinLimits returns the compiled-in matrix.
func builtinLimits() *limitsTable {
	return &limitsTable{
		Source: "built-in table",
		Rows: map[string]limitRow{
			rowAresOne:         {BGPv4: aresOneGroupV4, BGPv6: aresOneGroupV6, MaxFlows: aresOneMaxFlows},
			rowNovusNormal:     {BGPv4: novusNormalV4, BGPv6: novusNormalV6, MaxFlows: novus10GMaxFlows},
			rowNovusAggregated: {BGPv4: novusAggregatedV4, BGPv6: novusAggregatedV6, MaxFlows: novus10GMaxFlows},
			rowNovus32S:        {BGPv4: novus32SV4, BGPv6: novus32SV6, MaxFlows: novus10GMaxFlows},
			rowSert100G:        {BGPv4: sert100GV4, BGPv6: sert100GV6},
		},
	}
}

// findLimitsFile returns the path of the limits file to use, or "" when there is
// none. An explicit -scale_limits_file is required to exist.
func findLimitsFile(t *testing.T) string {
	t.Helper()
	if p := strings.TrimSpace(*limitsFile); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("-scale_limits_file=%s: %v", p, err)
		}
		return p
	}
	// The test binary runs with its own package directory as the working
	// directory, in both `go test ./dir/` and `go test dir/file.go` form, so
	// these two relative paths are the test's folder and its parent.
	for _, c := range []string{limitsFileName, filepath.Join("..", limitsFileName)} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// loadedLimits caches the table so the file is read, and its banner logged,
// once per run however many times discovery is called.
var loadedLimits *limitsTable

// loadCardLimits returns the matrix in force, applying card_limits.json on top
// of the built-in table when one is present. It is fatal on a file that exists
// but cannot be used.
func loadCardLimits(t *testing.T) *limitsTable {
	t.Helper()
	if loadedLimits != nil {
		return loadedLimits
	}
	tbl := builtinLimits()
	loadedLimits = tbl

	path := findLimitsFile(t)
	if path == "" {
		tbl.Source = fmt.Sprintf("built-in table (no %s alongside the test or in its parent directory)", limitsFileName)
		return tbl
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read card limits file %s: %v\n"+
			"\tremove the file to fall back to the built-in table", path, err)
	}
	var f limitsFileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("cannot parse card limits file %s: %v\n"+
			"\tfix the file or remove it to fall back to the built-in table", path, err)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	tbl.Source = abs
	tbl.Cards = f.Cards

	// Merge field by field so an omitted field keeps its built-in value, and
	// record what changed for the log.
	var changes []string
	for name, in := range f.Rows {
		row, known := tbl.Rows[name]
		before := row
		if in.BGPv4 != nil {
			row.BGPv4 = *in.BGPv4
		}
		if in.BGPv6 != nil {
			row.BGPv6 = *in.BGPv6
		}
		if in.MaxFlows != nil {
			row.MaxFlows = *in.MaxFlows
		}
		tbl.Rows[name] = row
		switch {
		case !known:
			changes = append(changes, fmt.Sprintf("%s: new row %d/%d sessions, %d flows", name, row.BGPv4, row.BGPv6, row.MaxFlows))
		case row != before:
			changes = append(changes, fmt.Sprintf("%s: %d/%d sessions, %d flows (built-in: %d/%d, %d)",
				name, row.BGPv4, row.BGPv6, row.MaxFlows, before.BGPv4, before.BGPv6, before.MaxFlows))
		}
	}
	sort.Strings(changes)
	for _, c := range f.Cards {
		changes = append(changes, fmt.Sprintf("card rule %q: %d/%d sessions, %d flows", c.Match, c.BGPv4, c.BGPv6, c.MaxFlows))
	}

	if len(changes) == 0 {
		t.Logf("card limits: %s found but it changes nothing; the built-in table is in force", abs)
		return tbl
	}
	border := strings.Repeat("-", 78)
	var b strings.Builder
	fmt.Fprintf(&b, "\n\t\tCard limits overridden by %s\n%s\n", abs, border)
	for _, c := range changes {
		fmt.Fprintf(&b, "\t\t%s\n", c)
	}
	fmt.Fprintf(&b, "%s\n", border)
	t.Log(b.String())
	return tbl
}

// portRef identifies one physical Ixia port the way an ondatra binding names
// it: "<chassis-host>;<card>;<port>".
type portRef struct {
	Chassis string
	Card    int
	Port    int
}

func (r portRef) String() string {
	return fmt.Sprintf("%s;%d;%d", r.Chassis, r.Card, r.Port)
}

// parsePortRef splits an ondatra binding port name into chassis, card and port.
func parsePortRef(name string) (portRef, error) {
	f := strings.Split(strings.TrimSpace(name), ";")
	if len(f) != 3 {
		return portRef{}, fmt.Errorf("port name %q is not in <chassis>;<card>;<port> form", name)
	}
	card, err := strconv.Atoi(strings.TrimSpace(f[1]))
	if err != nil {
		return portRef{}, fmt.Errorf("port name %q: bad card number: %v", name, err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(f[2]))
	if err != nil {
		return portRef{}, fmt.Errorf("port name %q: bad port number: %v", name, err)
	}
	return portRef{Chassis: strings.TrimSpace(f[0]), Card: card, Port: port}, nil
}

// topoPort is one port as reported by "show topology".
type topoPort struct {
	Number int
	Type   string // e.g. "400GBASE-CR8", "LAN SFP+", "10GBASE-T"
	Owner  string // "" when the port is not owned
	LinkUp bool
}

// resourceGroup is one resource group of a card. NumPorts and PortType are the
// two halves of the group's mode string: "2x400GBASE-CR8" is 2 ports of
// 400GBASE-CR8, "4xLAN" is 4 ports in LAN mode.
type resourceGroup struct {
	Number   int
	Mode     string // raw mode string, kept verbatim for logging
	NumPorts int
	PortType string
	Ports    []topoPort
}

// Aggregated reports whether the group runs in aggregated mode, where the whole
// group is presented as a single port.
func (g resourceGroup) Aggregated() bool {
	return strings.Contains(strings.ToLower(g.Mode), "aggregat") || g.NumPorts == 1
}

// chassisCard is one card of a chassis.
type chassisCard struct {
	Number int
	Type   string // e.g. "S400GD-16P-QDD", "NOVUS10/5/2.5/1/100M16DP"
	Serial string
	Groups []resourceGroup
}

// GroupForPort returns the resource group that owns the given port number.
func (c *chassisCard) GroupForPort(port int) *resourceGroup {
	for i := range c.Groups {
		for _, p := range c.Groups[i].Ports {
			if p.Number == port {
				return &c.Groups[i]
			}
		}
	}
	return nil
}

// chassisTopology is the "show topology" view of one chassis.
type chassisTopology struct {
	Host   string
	Name   string // e.g. "AresONE", "XGS2-HSL"
	Serial string
	Cards  []chassisCard
}

// CardByNumber returns the card in the given slot.
func (c *chassisTopology) CardByNumber(n int) *chassisCard {
	for i := range c.Cards {
		if c.Cards[i].Number == n {
			return &c.Cards[i]
		}
	}
	return nil
}

// cardLimits is the rated capacity of a single port.
type cardLimits struct {
	BGPv4 uint32
	BGPv6 uint32
	// MaxFlows is 0 when the card has no published flow rating.
	MaxFlows uint32
	// Source names the matrix row these numbers came from, so a run log records
	// why a limit was applied.
	Source string
}

// Sessions returns the session limit for address family afi, which is 4 or 6.
func (l cardLimits) Sessions(afi int) uint32 {
	if afi == 6 {
		return l.BGPv6
	}
	return l.BGPv4
}

// portHealth is the per-port health read over the IxOS REST API.
type portHealth struct {
	Port int
	// RestID is the port's IxOS REST resource id, which is what the port
	// operation endpoints are keyed by -- not the card/port numbers.
	RestID       int
	MemoryMB     int
	PcpuStatus   string
	ManagementIP string
	LinkState    string
	SpeedMbps    int
	Type         string
	Transceiver  string
	Owner        string
}

// chassisPerf is the chassis-level CPU / memory sample from the IxOS REST perf
// counters. IxOS exposes no per-port CPU figure, so this is the closest
// available proxy; per-port memory comes from portHealth.MemoryMB.
type chassisPerf struct {
	CPUPercent    float64
	MemInUseBytes uint64
	MemTotalBytes uint64
}

// MemPercent returns memory in use as a percentage of total.
func (p chassisPerf) MemPercent() float64 {
	if p.MemTotalBytes == 0 {
		return 0
	}
	return float64(p.MemInUseBytes) * 100 / float64(p.MemTotalBytes)
}

func (p chassisPerf) String() string {
	return fmt.Sprintf("cpu %.1f%%, memory %.2f/%.2f GiB (%.1f%%)",
		p.CPUPercent,
		float64(p.MemInUseBytes)/(1<<30), float64(p.MemTotalBytes)/(1<<30),
		p.MemPercent())
}

// resolvedPort ties one binding port name to the card and resource group it
// lives on and the limits that follow from them.
type resolvedPort struct {
	Ref    portRef
	Card   *chassisCard
	Group  *resourceGroup
	Limits cardLimits
	Health *portHealth // nil when REST was unavailable
}

// chassisInventory is the result of discovering every port the test will use.
type chassisInventory struct {
	Chassis []*chassisTopology
	Ports   []resolvedPort
	// RESTErrs records, per chassis host, why the REST API could not be used.
	// Discovery still succeeds in that case, with Health left nil.
	RESTErrs map[string]error
	// LimitsSource is where the rating matrix came from, quoted in the log so a
	// run always records which table produced the limits it applied.
	LimitsSource string
}

// discoverPorts reads the topology of every chassis referenced by portNames and
// resolves each port to its card, resource group and rated limits. portNames
// are ondatra binding names ("<chassis>;<card>;<port>").
func discoverPorts(user, pass string, portNames []string, timeout time.Duration, tbl *limitsTable) (*chassisInventory, error) {
	refs := make([]portRef, 0, len(portNames))
	for _, n := range portNames {
		r, err := parsePortRef(n)
		if err != nil {
			return nil, err
		}
		refs = append(refs, r)
	}

	inv := &chassisInventory{RESTErrs: map[string]error{}, LimitsSource: tbl.Source}
	byHost := map[string]*chassisTopology{}
	health := map[string]map[int]map[int]*portHealth{} // host -> card -> port

	for _, r := range refs {
		if _, ok := byHost[r.Chassis]; ok {
			continue
		}
		out, err := runIxOSCommand(r.Chassis, user, pass, "show topology", timeout)
		if err != nil {
			return nil, fmt.Errorf("chassis %s: show topology: %v", r.Chassis, err)
		}
		ch, err := parseTopology(out)
		if err != nil {
			return nil, fmt.Errorf("chassis %s: %v", r.Chassis, err)
		}
		ch.Host = r.Chassis
		byHost[r.Chassis] = ch
		inv.Chassis = append(inv.Chassis, ch)

		if h, err := fetchAllPortHealth(r.Chassis, user, pass, timeout); err != nil {
			inv.RESTErrs[r.Chassis] = err
		} else {
			health[r.Chassis] = h
		}
	}

	for _, r := range refs {
		ch := byHost[r.Chassis]
		rp := resolvedPort{Ref: r}
		card := ch.CardByNumber(r.Card)
		if card == nil {
			return nil, fmt.Errorf("chassis %s has no card %d", r.Chassis, r.Card)
		}
		rp.Card = card
		rp.Group = card.GroupForPort(r.Port)
		if rp.Group == nil {
			return nil, fmt.Errorf("chassis %s card %d has no port %d", r.Chassis, r.Card, r.Port)
		}
		rp.Limits = limitsFor(ch, card, *rp.Group, tbl)
		if byCard, ok := health[r.Chassis]; ok {
			if byPort, ok := byCard[r.Card]; ok {
				rp.Health = byPort[r.Port]
			}
		}
		inv.Ports = append(inv.Ports, rp)
	}
	return inv, nil
}

// MinLimits returns the tightest limit across every resolved port, which is
// what a test spanning those ports has to respect.
func (inv *chassisInventory) MinLimits() cardLimits {
	var out cardLimits
	for i, p := range inv.Ports {
		if i == 0 {
			out = p.Limits
			continue
		}
		if p.Limits.BGPv4 < out.BGPv4 {
			out.BGPv4 = p.Limits.BGPv4
			out.Source = p.Limits.Source
		}
		if p.Limits.BGPv6 < out.BGPv6 {
			out.BGPv6 = p.Limits.BGPv6
		}
		// A zero MaxFlows means "unrated"; a rated cap always wins over it.
		if p.Limits.MaxFlows != 0 && (out.MaxFlows == 0 || p.Limits.MaxFlows < out.MaxFlows) {
			out.MaxFlows = p.Limits.MaxFlows
		}
	}
	return out
}

// SameResourceGroup reports whether every resolved port shares one resource
// group. When they do, the ports compete for a single group's capacity rather
// than each getting the rated per-port figure.
func (inv *chassisInventory) SameResourceGroup() bool {
	if len(inv.Ports) < 2 {
		return false
	}
	first := inv.Ports[0]
	for _, p := range inv.Ports[1:] {
		if p.Ref.Chassis != first.Ref.Chassis || p.Ref.Card != first.Ref.Card ||
			p.Group.Number != first.Group.Number {
			return false
		}
	}
	return true
}

// String renders the discovered inventory as a log block.
func (inv *chassisInventory) String() string {
	border := strings.Repeat("-", 78)
	var b strings.Builder
	fmt.Fprintf(&b, "\n\t\tIxia chassis / card inventory\n%s\n", border)
	fmt.Fprintf(&b, "\t\trating matrix   : %s\n", inv.LimitsSource)
	for _, ch := range inv.Chassis {
		fmt.Fprintf(&b, "\t\tchassis %s: %s (SN %s)\n", ch.Host, ch.Name, ch.Serial)
		if err := inv.RESTErrs[ch.Host]; err != nil {
			fmt.Fprintf(&b, "\t\t  REST API unavailable (%v); port memory / PCPU status not read\n", err)
		}
	}
	for _, p := range inv.Ports {
		fmt.Fprintf(&b, "%s\n", border)
		fmt.Fprintf(&b, "\t\tport %s\n", p.Ref)
		fmt.Fprintf(&b, "\t\t  card %d          : %s (SN %s)\n", p.Card.Number, p.Card.Type, p.Card.Serial)
		fmt.Fprintf(&b, "\t\t  resource group  : RG%02d, mode %q (%d ports of %s)\n",
			p.Group.Number, p.Group.Mode, p.Group.NumPorts, p.Group.PortType)
		fmt.Fprintf(&b, "\t\t  rated BGPv4/v6  : %d / %d sessions per port  [%s]\n",
			p.Limits.BGPv4, p.Limits.BGPv6, p.Limits.Source)
		if p.Limits.MaxFlows > 0 {
			fmt.Fprintf(&b, "\t\t  rated max flows : %d\n", p.Limits.MaxFlows)
		} else {
			fmt.Fprintf(&b, "\t\t  rated max flows : not rated for this card\n")
		}
		if h := p.Health; h != nil {
			fmt.Fprintf(&b, "\t\t  port memory     : %d MB\n", h.MemoryMB)
			fmt.Fprintf(&b, "\t\t  port CPU (PCPU) : %s (mgmt %s)\n", h.PcpuStatus, h.ManagementIP)
			fmt.Fprintf(&b, "\t\t  link/speed/type : %s / %d Mbps / %s\n", h.LinkState, h.SpeedMbps, h.Type)
			fmt.Fprintf(&b, "\t\t  transceiver     : %s\n", h.Transceiver)
			fmt.Fprintf(&b, "\t\t  owner           : %s\n", h.Owner)
		}
	}
	if inv.SameResourceGroup() {
		fmt.Fprintf(&b, "%s\n", border)
		fmt.Fprintf(&b, "\t\tNOTE: all ports under test share one resource group; the rated\n")
		fmt.Fprintf(&b, "\t\tfigure above is per port, so the group carries their sum.\n")
	}
	fmt.Fprintf(&b, "%s\n", border)
	return b.String()
}

// limitsFor picks the performance-matrix row for a card in a given group mode,
// out of the table in force (built-in, or card_limits.json applied on top).
func limitsFor(ch *chassisTopology, card *chassisCard, g resourceGroup, tbl *limitsTable) cardLimits {
	t := strings.ToUpper(card.Type)

	// A card rule from the file wins over every built-in rule, so a card the
	// matrix has no row for can be rated without editing this test.
	for _, c := range tbl.Cards {
		if c.Match == "" || !strings.Contains(t, strings.ToUpper(c.Match)) {
			continue
		}
		src := c.Source
		if src == "" {
			src = fmt.Sprintf("%s rule %q", limitsFileName, c.Match)
		}
		if c.PerGroup {
			return splitOverGroup(c.BGPv4, c.BGPv6, c.MaxFlows, g, src)
		}
		return cardLimits{BGPv4: c.BGPv4, BGPv6: c.BGPv6, MaxFlows: c.MaxFlows, Source: src}
	}

	isAresOne := strings.HasPrefix(t, "S400GD") || strings.HasPrefix(t, "S800G") ||
		strings.Contains(strings.ToUpper(ch.Name), "ARESONE")

	switch {
	case isAresOne:
		r := tbl.Rows[rowAresOne]
		return splitOverGroup(r.BGPv4, r.BGPv6, r.MaxFlows, g,
			fmt.Sprintf("AresONE %s, %dx%s", card.Type, g.NumPorts, g.PortType))

	case strings.Contains(t, "SERT"):
		r := tbl.Rows[rowSert100G]
		return cardLimits{BGPv4: r.BGPv4, BGPv6: r.BGPv6, MaxFlows: r.MaxFlows, Source: "SERT 100G (100GE-QSFP28)"}

	case strings.Contains(t, "1GE32S"):
		r := tbl.Rows[rowNovus32S]
		return cardLimits{
			BGPv4:    r.BGPv4,
			BGPv6:    r.BGPv6,
			MaxFlows: r.MaxFlows,
			Source:   "NOVUS10/1GE32S",
		}

	case isNovus10G(t):
		// NOVUS-NP10/1GE16DP has no aggregated-mode row in the matrix.
		if g.Aggregated() && !strings.Contains(t, "NP10") {
			r := tbl.Rows[rowNovusAggregated]
			return cardLimits{
				BGPv4:    r.BGPv4,
				BGPv6:    r.BGPv6,
				MaxFlows: r.MaxFlows,
				Source:   fmt.Sprintf("NOVUS10/1GE/100M aggregated mode (%s, mode %q)", card.Type, g.Mode),
			}
		}
		r := tbl.Rows[rowNovusNormal]
		return cardLimits{
			BGPv4:    r.BGPv4,
			BGPv6:    r.BGPv6,
			MaxFlows: r.MaxFlows,
			Source:   fmt.Sprintf("NOVUS10/1GE/100M normal mode (%s, mode %q)", card.Type, g.Mode),
		}
	}

	return cardLimits{Source: fmt.Sprintf("card %q has no row in the performance matrix; no limit enforced", card.Type)}
}

// splitOverGroup rates a resource group whose published figure is a whole-group
// total, divided evenly over however many ports the group is broken out into.
// That is how AresONE is rated, and it is why the matrix columns halve as the
// port count doubles.
func splitOverGroup(groupV4, groupV6, maxFlows uint32, g resourceGroup, what string) cardLimits {
	n := uint32(g.NumPorts)
	if n == 0 {
		n = 1
	}
	// Round to nearest, matching the published columns (36556/16 = 2285).
	return cardLimits{
		BGPv4:    (groupV4 + n/2) / n,
		BGPv6:    (groupV6 + n/2) / n,
		MaxFlows: maxFlows,
		Source:   fmt.Sprintf("%s: %d/%d per group split %d ways", what, groupV4, groupV6, n),
	}
}

// isNovus10G reports whether an upper-cased card type is one of the
// NOVUS10/1GE/100M family rows of the matrix.
func isNovus10G(t string) bool {
	for _, p := range []string{"NOVUS10/", "NOVUS-NP10/", "NOVUS1GE"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return strings.HasPrefix(t, "NOVUS ONE") || strings.HasPrefix(t, "NOVUSONE")
}

var (
	// "XGS2-HSL - Primary (ChassisSN XGS2-G0960034, ControllerSN 606488)"
	// "AresONE - Primary (ChassisSN MY26131006)"
	reChassis = regexp.MustCompile(`^\s*(\S+)\s+-\s+\S+\s+\(ChassisSN\s+([^,)]+)`)
	// "    +- Card 1 S400GD-16P-QDD (SN MY26131006)"
	reCard = regexp.MustCompile("^\\s*[+`|-]+-\\s*Card\\s+(\\d+)\\s+(\\S+)(?:\\s+\\(SN\\s+([^)]*)\\))?")
	// "|      +- Resource Group 01 (RG01)- 2x400GBASE-CR8 mode"
	reGroup = regexp.MustCompile(`Resource Group\s+(\d+)\s*\(RG\d+\)\s*-\s*(.+?)\s+mode\s*$`)
	// "|      +- Port 9 400GBASE-CR8 (8b0f3376498d/root/1) Link Up"
	// "|      |- Port 11 10GBASE-T Link Up"
	rePort = regexp.MustCompile(`Port\s+(\d+)\s+(.+?)(?:\s+\(([^)]*)\))?\s+Link\s+(Up|Down)\s*$`)
	// "2x400GBASE-CR8", "4xLAN"
	reMode = regexp.MustCompile(`^(\d+)x(.+)$`)
)

// parseTopology parses the output of the IxOS CLI "show topology" command.
func parseTopology(out string) (*chassisTopology, error) {
	ch := &chassisTopology{}
	var card *chassisCard
	var group *resourceGroup

	// flushGroup/flushCard attach whatever is being accumulated to its parent.
	flushGroup := func() {
		if group != nil && card != nil {
			card.Groups = append(card.Groups, *group)
		}
		group = nil
	}
	flushCard := func() {
		flushGroup()
		if card != nil {
			ch.Cards = append(ch.Cards, *card)
		}
		card = nil
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r \t")
		if line == "" {
			continue
		}
		switch {
		case ch.Name == "" && reChassis.MatchString(line):
			m := reChassis.FindStringSubmatch(line)
			ch.Name, ch.Serial = m[1], strings.TrimSpace(m[2])

		case reCard.MatchString(line):
			flushCard()
			m := reCard.FindStringSubmatch(line)
			n, _ := strconv.Atoi(m[1])
			card = &chassisCard{Number: n, Type: m[2], Serial: strings.TrimSpace(m[3])}

		case reGroup.MatchString(line):
			flushGroup()
			m := reGroup.FindStringSubmatch(line)
			n, _ := strconv.Atoi(m[1])
			group = &resourceGroup{Number: n, Mode: m[2]}
			if mm := reMode.FindStringSubmatch(group.Mode); mm != nil {
				group.NumPorts, _ = strconv.Atoi(mm[1])
				group.PortType = mm[2]
			}

		case rePort.MatchString(line):
			if group == nil {
				continue
			}
			m := rePort.FindStringSubmatch(line)
			n, _ := strconv.Atoi(m[1])
			group.Ports = append(group.Ports, topoPort{
				Number: n,
				Type:   strings.TrimSpace(m[2]),
				Owner:  strings.TrimSpace(m[3]),
				LinkUp: m[4] == "Up",
			})
		}
	}
	flushCard()

	if len(ch.Cards) == 0 {
		return nil, fmt.Errorf("no cards found in \"show topology\" output:\n%s", out)
	}
	return ch, nil
}

// runIxOSCommand runs one command in the restricted IxOS CLI over SSH and
// returns its stdout.
func runIxOSCommand(host, user, pass, cmd string, timeout time.Duration) (string, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // lab chassis, as elsewhere in this suite
		Timeout:         timeout,
	}
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %v", addr, err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("%q: %v (output: %s)", cmd, err, string(out))
	}
	return string(out), nil
}

// ixosREST is a thin IxOS REST client, authenticated with a platform session
// API key.
type ixosREST struct {
	host   string
	apiKey string
	client *http.Client
}

func newIxosREST(host, user, pass string, timeout time.Duration) (*ixosREST, error) {
	c := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Chassis serve a self-signed certificate.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, err := c.Post("https://"+host+"/platform/api/v1/auth/session",
		"application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("auth: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var out struct {
		APIKey string `json:"apiKey"`
		Error  string `json:"error"`
		// A chassis on a default password refuses to issue a session until the
		// password is changed.
		ResetWeakPassword bool `json:"resetWeakPassword"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("auth: bad response %q", string(raw))
	}
	if out.APIKey == "" {
		msg := out.Error
		if msg == "" {
			msg = string(raw)
		}
		if out.ResetWeakPassword {
			msg += " (chassis requires the default password to be changed before it will issue an API session)"
		}
		return nil, fmt.Errorf("auth: %s", msg)
	}
	return &ixosREST{host: host, apiKey: out.APIKey, client: c}, nil
}

// post issues a POST against the chassis REST API. Operation endpoints return
// 200/202/204 with no body worth reading, so only the status is checked.
func (r *ixosREST) post(path string, body any) error {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+r.host+"/chassis/api/v2/"+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", r.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("POST %s: %s: %s", path, resp.Status, strings.TrimSpace(string(raw)))
	}
	return nil
}

func (r *ixosREST) get(path string, into any) error {
	req, err := http.NewRequest(http.MethodGet, "https://"+r.host+"/chassis/api/v2/"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", r.apiKey)
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(raw)))
	}
	return json.Unmarshal(raw, into)
}

// fetchAllPortHealth reads every port on the chassis, keyed by card then port.
func fetchAllPortHealth(host, user, pass string, timeout time.Duration) (map[int]map[int]*portHealth, error) {
	r, err := newIxosREST(host, user, pass, timeout)
	if err != nil {
		return nil, err
	}
	var ports []struct {
		ID               int    `json:"id"`
		CardNumber       int    `json:"cardNumber"`
		PortNumber       int    `json:"portNumber"`
		PortMemory       int    `json:"portMemory"`
		PcpuStatus       string `json:"pcpuStatus"`
		ManagementIP     string `json:"managementIp"`
		LinkState        string `json:"linkState"`
		Speed            int    `json:"speed"`
		Type             string `json:"type"`
		TransceiverModel string `json:"transceiverModel"`
		Owner            string `json:"owner"`
	}
	if err := r.get("ixos/ports", &ports); err != nil {
		return nil, err
	}
	out := map[int]map[int]*portHealth{}
	for _, p := range ports {
		if out[p.CardNumber] == nil {
			out[p.CardNumber] = map[int]*portHealth{}
		}
		out[p.CardNumber][p.PortNumber] = &portHealth{
			Port:         p.PortNumber,
			RestID:       p.ID,
			MemoryMB:     p.PortMemory,
			PcpuStatus:   p.PcpuStatus,
			ManagementIP: p.ManagementIP,
			LinkState:    p.LinkState,
			SpeedMbps:    p.Speed,
			Type:         p.Type,
			Transceiver:  p.TransceiverModel,
			Owner:        p.Owner,
		}
	}
	return out, nil
}

// fetchChassisPerf returns the most recent chassis CPU / memory sample. IxOS
// keeps a rolling window of samples; the last one is the freshest.
func fetchChassisPerf(host, user, pass string, timeout time.Duration) (*chassisPerf, error) {
	r, err := newIxosREST(host, user, pass, timeout)
	if err != nil {
		return nil, err
	}
	var samples []struct {
		Sequence      uint64  `json:"sequence"`
		MemInUseBytes uint64  `json:"memoryInUseBytes"`
		MemTotalBytes uint64  `json:"memoryTotalBytes"`
		CPUPercent    float64 `json:"cpuUsagePercent"`
	}
	if err := r.get("ixos/perfcounters", &samples); err != nil {
		return nil, err
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("no perf counter samples returned")
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].Sequence < samples[j].Sequence })
	last := samples[len(samples)-1]
	return &chassisPerf{
		CPUPercent:    last.CPUPercent,
		MemInUseBytes: last.MemInUseBytes,
		MemTotalBytes: last.MemTotalBytes,
	}, nil
}

// fetchPortHealthFor re-reads the per-port memory / PCPU status for the given
// ports, so a caller can sample it again after a run.
func fetchPortHealthFor(user, pass string, refs []portRef, timeout time.Duration) (map[string]*portHealth, error) {
	byHost := map[string]map[int]map[int]*portHealth{}
	out := map[string]*portHealth{}
	for _, r := range refs {
		if _, ok := byHost[r.Chassis]; !ok {
			h, err := fetchAllPortHealth(r.Chassis, user, pass, timeout)
			if err != nil {
				return nil, err
			}
			byHost[r.Chassis] = h
		}
		if byCard, ok := byHost[r.Chassis][r.Card]; ok {
			if p, ok := byCard[r.Port]; ok {
				out[r.String()] = p
			}
		}
	}
	return out, nil
}
