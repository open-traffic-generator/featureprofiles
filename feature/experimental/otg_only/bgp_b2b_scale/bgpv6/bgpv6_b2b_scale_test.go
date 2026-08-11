// Package otg_b2b_bgpv6_scale is an OTG-only BGPv6 session scale test over an
// ATE port1 <-> port2 back-to-back link, using ondatra + gosnappi + OTG gNMI
// telemetry only. It mirrors ../bgpv4/bgpv4_b2b_scale_test.go, configuring
// BGPv6 peers over IPv6 interfaces (Ipv6Interfaces / BgpV6Peer / V6Routes).
//
// N sessions are brought up on each port (2*N peers total, each port1 peer
// paired with the port2 peer facing it), every peer advertises a /128 route
// range, and session state and route counters are read back over OTG gNMI
// (BgpPeer telemetry is AFI-agnostic, so the same paths serve v4 and v6 peers).
// A capped number of data-plane flows over the advertised routes is used as a
// sanity check. Every device is double tagged (outer QinQ + inner dot1q) with a
// per-session tag pair, so each session pair sits in its own broadcast domain,
// and the port L1 MTU is raised to carry those tags. All peers are iBGP in one
// AS, and each peer's router ID is a unique, non-zero IPv4 address.
//
// Each iteration reboots the ports, pushes the config, brings up the sessions,
// reads telemetry and runs traffic. Every API call is timed and each iteration
// ends with a timing table.
//
// The rig plumbing and the OTG mechanics live in ../../scale: chassis discovery
// and the card rating matrix, port reboot, API timing, the addressing
// arithmetic, the per-device and per-flow gosnappi calls, and the telemetry
// fetches. What stays here is what this test does and what it asserts.
//
// See README.md one directory up for the flags, the card rating matrix and the
// full run instructions.
//
// Example:
//
//	go test -v ./feature/experimental/otg_only/bgp_b2b_scale/bgpv6/bgpv6_b2b_scale_test.go \
//	  -timeout 60m -binding <path>/otgb2b-hw.binding -testbed <path>/otgb2b-hw.testbed \
//	  -scale_sessions=1000 -scale_routes=1 -scale_max_flows=256 -scale_session_timeout=10m
package otg_b2b_bgpv6_scale

import (
	"flag"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/feature/experimental/otg_only/scale"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	otg "github.com/openconfig/ondatra/otg"
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
	dumpConfig     = flag.Bool("scale_dump_config", false, "log the pushed OTG config as JSON")

	// Addressing. Every session pair gets its own /64: session i sits in
	// <subnetBase with the 4th hextet set to i>::/64, with ::1 on port1 and ::2
	// on port2, each side using the other as gateway / BGP peer. One subnet per
	// session keeps every pair in its own broadcast domain.
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
	l1MTU       = flag.Uint("scale_l1_mtu", 1516, "port layer1 MTU; the default carries the two VLAN tags on top of the 1500 byte device MTU")

	// Optional non-default BGP TCP ports. Both must be set to take effect; the two
	// sides mirror each other, so what port1 listens on is what port2 connects to.
	listenPort   = flag.Uint("scale_listen_port", 0, "non-default BGP listen port on port1 peers (0 = leave the default 179)")
	neighborPort = flag.Uint("scale_neighbor_port", 0, "non-default BGP neighbor port on port1 peers (0 = leave the default 179)")
)

const (
	// afiName labels this test's address family in its log output, and afi selects
	// the column of the card rating matrix to check against. The v6 column is the
	// tighter of the two.
	afiName = "BGPv6"
	afi     = 6

	p1MACStart = "02:00:01:00:00:01"
	p2MACStart = "02:00:02:00:00:01"

	// Advertised route range bases, one contiguous block per peer.
	p1RouteStart = "2001:db8:100::1"
	p2RouteStart = "2001:db8:200::1"
	routePrefix  = 128

	// Per-device ethernet MTU.
	ethMTU = 1500

	tolerancePct = 2.0
	// Loss tolerance in packets, matching the reference b2b test.
	tolerancePkts = 50
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// scaleConfig is the pushed config plus the names the verification steps need to
// query: peerNames holds the configured peers per side, in device order.
type scaleConfig struct {
	config    gosnappi.Config
	peers     []string // all configured BGPv6 peer names, both ports
	flowNames []string
}

// sides describes the two ends of the b2b link. port1 devices take ::1 of each
// session subnet and port2 devices ::2, each using the other as its gateway and
// BGP peer.
var sides = []struct {
	port, pfx, macStart, routeStart string
	routerIDBase                    *string
	host, gwHost                    byte
}{
	{"port1", "p1", p1MACStart, p1RouteStart, p1RouterID, 1, 2},
	{"port2", "p2", p2MACStart, p2RouteStart, p2RouterID, 2, 1},
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
	defer scale.LogWarnings(t)

	// Resolve the bound ports to a real card and resource group, and warn when
	// the requested scale is above what the card is rated for.
	inv := scale.DiscoverChassis(t, ate)
	scale.CheckSessionLimit(t, inv, sessions, afi)
	if *runTraffic {
		scale.CheckFlowLimit(t, inv, uint32(*maxFlows))
	}

	// Put the ports into the controller's config before the run proper, so that
	// the OTG reboot action has ports to name from the very first iteration.
	otgPortNames := scale.SeedPortConfig(t, otgDev)

	for itr := uint(0); itr < *iterations; itr++ {
		t.Logf("=== iteration %d/%d : %d sessions/port (%d peers total), %d routes/peer ===",
			itr+1, *iterations, sessions, 2*sessions, routes)
		start := time.Now()
		scale.APITime.Reset()

		// Every iteration starts on freshly rebooted ports.
		scale.RebootPorts(t, ate, otgPortNames)

		scale.LogCardHealth(t, inv, fmt.Sprintf("iteration %d, before config", itr+1))

		sc := buildScaleConfig(t, sessions, routes)

		if *dumpConfig {
			if j, err := sc.config.Marshal().ToJson(); err == nil {
				t.Logf("OTG config:\n%s", j)
			}
		}

		t.Logf("Pushing config to ATE (%d devices, %d peers, %d flows)...",
			len(sc.config.Devices().Items()), len(sc.peers), len(sc.flowNames))
		scale.APITime.Call(t, scale.APISetConfig, func() { otgDev.PushConfig(t, sc.config) })
		scale.APITime.Call(t, scale.APIStartProtocols, func() { otgDev.StartProtocols(t) })

		scale.LogPortAndNDState(t, otgDev, sc.config, 10)

		upStart := time.Now()
		awaitSessionsEstablished(t, otgDev, sc.peers, *sessionTimeout)
		t.Logf("All %d %s sessions ESTABLISHED in %v", len(sc.peers), afiName, time.Since(upStart))

		verifyBGPCounters(t, otgDev, sc.peers, sessions, routes, *metricsTimeout)

		if *runTraffic && len(sc.flowNames) > 0 {
			sendTraffic(t, otgDev, sc.flowNames)
			verifyTraffic(t, otgDev, sc.flowNames)
		}

		// Sampled while the sessions are still up, so the figures reflect the
		// loaded card rather than an idle one.
		scale.LogCardHealth(t, inv, fmt.Sprintf("iteration %d, at full scale", itr+1))

		scale.APITime.Call(t, scale.APIStopProtocols, func() { otgDev.StopProtocols(t) })

		t.Log(scale.APITime.String(fmt.Sprintf("iteration %d/%d, %d sessions/port", itr+1, *iterations, sessions)))
		t.Logf("=== iteration %d/%d completed in %v ===", itr+1, *iterations, time.Since(start))
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

	for _, side := range sides {
		for i := uint32(1); i <= sessions; i++ {
			peer := scale.AddBGPv6Device(t, config, scale.DeviceSpec{
				PortName:   side.port,
				SidePrefix: side.pfx,
				Index:      i,
				MAC:        scale.MACFor(t, side.macStart, i),
				EthMTU:     ethMTU,
				DevIP:      scale.SessionIPv6(t, *subnetBase, i, side.host),
				GwIP:       scale.SessionIPv6(t, *subnetBase, i, side.gwHost),
				IPPrefix:   uint32(*ipPrefix),
				RouterID:   scale.RouterIDFor(t, *side.routerIDBase, i),
				// Every peer is iBGP in the same AS.
				AS:             uint32(*asNum),
				Routes:         routes,
				RouteStart:     scale.RouteStartIPv6(side.routeStart, i, routes),
				RoutePrefix:    routePrefix,
				RouteRangeName: routeRangeName(side.pfx, i),
				VLAN:           *vlanTagging,
				QinQ:           *qinqTagging,
				ListenPort:     uint32(*listenPort),
				NeighborPort:   uint32(*neighborPort),
			})
			sc.peers = append(sc.peers, peer)
		}
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
			scale.AddIPv6Flow(config, scale.FlowSpec{
				Name:     name,
				TxNames:  []string{txRR},
				RxNames:  []string{rxRR},
				Index:    i,
				SrcMAC:   scale.MACFor(t, p1MACStart, i),
				DstMAC:   scale.MACFor(t, p2MACStart, i),
				SrcStart: scale.RouteStartIPv6(p1RouteStart, i, routes),
				DstStart: scale.RouteStartIPv6(p2RouteStart, i, routes),
				Count:    routes,
				Packets:  uint32(*flowPackets),
				Pps:      uint32(*flowPps),
				Size:     uint32(*flowSize),
				VLAN:     *vlanTagging,
				QinQ:     *qinqTagging,
			})
			sc.flowNames = append(sc.flowNames, name)
		}
	}
	return sc
}

func routeRangeName(sidePfx string, i uint32) string {
	return sidePfx + "rr" + strconv.Itoa(int(i))
}

// awaitSessionsEstablished polls OTG gNMI until every configured peer reports
// ESTABLISHED, backing off less aggressively as sessions come up.
func awaitSessionsEstablished(t *testing.T, otgDev *otg.OTG, peers []string, timeout time.Duration) {
	t.Helper()
	want := len(peers)
	deadline := time.Now().Add(timeout)
	base := scale.PollInterval(want)
	start := time.Now()

	for {
		stStart := time.Now()
		st := scale.BGPSessionStates(t, otgDev, peers)
		stTook := scale.APITime.Track(scale.APIGetBGPStates, stStart)

		ctStart := time.Now()
		c := scale.BGPCounters(t, otgDev, peers)
		ctTook := scale.APITime.Track(scale.APIGetBGPCounters, ctStart)

		t.Logf("[t+%-6v] %s sessions ESTABLISHED: %d/%d | GetMetrics: state %v, counters %v | states: %s%s",
			time.Since(start).Truncate(time.Second), afiName, st.Up, want,
			stTook.Round(time.Millisecond), ctTook.Round(time.Millisecond),
			st.Histogram(), st.DownList())
		t.Log(c.String(afiName, uint64(want), 0))
		if st.Up == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v: %d/%d %s sessions ESTABLISHED (states: %s)", timeout, st.Up, want, afiName, st.Histogram())
		}
		time.Sleep(scale.AdaptivePollInterval(base, st.Up, want))
	}
}

// verifyBGPCounters polls the aggregated BGP peer counters until the advertised /
// received route counts match expectation, and fails on any session flap.
func verifyBGPCounters(t *testing.T, otgDev *otg.OTG, peers []string, sessions, routes uint32, timeout time.Duration) {
	t.Helper()
	// Both ports advertise a route range, so every peer sends and receives
	// `routes` routes.
	wantRoutes := uint64(2*sessions) * uint64(routes)
	deadline := time.Now().Add(timeout)
	base := scale.PollInterval(len(peers))

	for {
		ctStart := time.Now()
		c := scale.BGPCounters(t, otgDev, peers)
		t.Logf("GetMetrics: BGP peer counters for %d peers took %v",
			len(peers), scale.APITime.Track(scale.APIGetBGPCounters, ctStart).Round(time.Millisecond))
		t.Log(c.String(afiName, uint64(len(peers)), wantRoutes))

		ok := c.Flaps == 0 && c.InRoutes == wantRoutes && c.OutRoutes == wantRoutes &&
			c.InRouteWithdraw == 0 && c.OutRouteWithdraw == 0
		if ok {
			return
		}
		if c.Flaps > 0 {
			t.Errorf("BGP session flaps: got %d, want 0", c.Flaps)
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("timed out after %v waiting for BGP route counters: in-routes got %d want %d, out-routes got %d want %d, withdraws in/out %d/%d want 0/0",
				timeout, c.InRoutes, wantRoutes, c.OutRoutes, wantRoutes, c.InRouteWithdraw, c.OutRouteWithdraw)
			return
		}
		time.Sleep(base)
	}
}

// sendTraffic starts the fixed-packet flows and waits for every flow to finish
// transmitting before stopping traffic.
func sendTraffic(t *testing.T, otgDev *otg.OTG, flowNames []string) {
	t.Helper()
	wantPkts := uint64(*flowPackets)
	txTime := time.Duration(float64(*flowPackets) / float64(*flowPps) * float64(time.Second))
	t.Logf("Starting traffic on %d flows (%d packets @ %d pps => %v of transmit per flow)",
		len(flowNames), wantPkts, *flowPps, txTime)
	scale.APITime.Call(t, scale.APIStartTraffic, func() { otgDev.StartTraffic(t) })

	scale.AwaitFlowsStopped(t, otgDev, flowNames, wantPkts, *trafficTimeout)

	t.Logf("Stopping traffic")
	scale.APITime.Call(t, scale.APIStopTraffic, func() { otgDev.StopTraffic(t) })
}

// verifyTraffic checks, per flow, that the full packet count was transmitted and
// that rx matches tx.
func verifyTraffic(t *testing.T, otgDev *otg.OTG, flowNames []string) {
	t.Helper()
	wantPkts := uint64(*flowPackets)
	fetchStart := time.Now()
	stats := scale.FlowCounters(t, otgDev, flowNames)
	fetchTook := scale.APITime.Track(scale.APIGetFlowMetrics, fetchStart)

	var totalTx, totalRx uint64
	shortTx, lossy := 0, 0
	for _, f := range stats {
		totalTx += f.Tx
		totalRx += f.Rx
		if f.Tx < wantPkts {
			t.Errorf("flow %s transmitted %d packets, want %d", f.Name, f.Tx, wantPkts)
			shortTx++
		}
		if f.Tx == 0 {
			continue
		}
		lost := int64(f.Tx) - int64(f.Rx)
		lossPct := float64(lost) * 100 / float64(f.Tx)
		if lost > tolerancePkts && lossPct > tolerancePct {
			t.Errorf("flow %s loss: tx %d, rx %d, loss %.2f%%, want <= %.2f%%", f.Name, f.Tx, f.Rx, lossPct, tolerancePct)
			lossy++
		}
	}

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
