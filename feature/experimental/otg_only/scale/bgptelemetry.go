package scale

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/ondatra/gnmi"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	otg "github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
)

// ---------------------------------------------------------------------------
// BGP telemetry over OTG gNMI
//
// Fetching and aggregation only. What to wait for, how long, and what counts as
// correct stay with the test. Both fetches prefer a single wildcard query and
// fall back to per-peer queries, permanently, the first time the wildcard
// returns nothing -- see -scale_wildcard_telemetry.
// ---------------------------------------------------------------------------

// SessionSummary is the distribution of session states over all peers.
type SessionSummary struct {
	// Up is the number of peers reporting ESTABLISHED; Reported is how many
	// reported any state at all.
	Up, Reported int
	ByState      map[string]int
	// Down is a capped sample of "peer=STATE" for peers not ESTABLISHED.
	Down []string
}

// Histogram renders the state distribution as "STATE=count" pairs.
func (s SessionSummary) Histogram() string {
	if s.Reported == 0 {
		return "no peer reported a session state"
	}
	keys := make([]string, 0, len(s.ByState))
	for k := range s.ByState {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, s.ByState[k]))
	}
	return strings.Join(parts, " ")
}

// DownList renders the sample of peers that are not ESTABLISHED, as a trailing
// log line, or "" when every peer is up.
func (s SessionSummary) DownList() string {
	if len(s.Down) == 0 {
		return ""
	}
	return "\n\tnot ESTABLISHED (sample): " + strings.Join(s.Down, ", ")
}

// BGPSessionStates reads the session state of every configured peer.
func BGPSessionStates(t *testing.T, otgDev *otg.OTG, peers []string) SessionSummary {
	t.Helper()
	const maxDownLogged = 10
	s := SessionSummary{ByState: map[string]int{}}

	record := func(name string, st otgtelemetry.E_BgpPeer_SessionState) {
		s.Reported++
		s.ByState[st.String()]++
		if st == otgtelemetry.BgpPeer_SessionState_ESTABLISHED {
			s.Up++
		} else if len(s.Down) < maxDownLogged {
			s.Down = append(s.Down, fmt.Sprintf("%s=%s", name, st.String()))
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

// BGPCounterSum is the sum of the peer counters over every peer that reported.
type BGPCounterSum struct {
	Peers                               uint64
	Flaps                               uint64
	InOpens, OutOpens                   uint64
	InKeepalives, OutKeepalives         uint64
	InUpdates, OutUpdates               uint64
	InNotifications, OutNotifications   uint64
	InRoutes, OutRoutes                 uint64
	InRouteWithdraw, OutRouteWithdraw   uint64
	InEndOfRib                          uint64
	PeersWithOpens, PeersWithKeepalives uint64
}

// String renders the aggregated counters. family labels the address family in
// the heading, e.g. "BGPv4". wantRoutes == 0 means "route counts are not being
// checked yet" (used while sessions are still coming up).
func (c BGPCounterSum) String(family string, wantPeers, wantRoutes uint64) string {
	border := strings.Repeat("-", 78)
	routeExp := "(Expected : n/a yet)"
	if wantRoutes > 0 {
		routeExp = fmt.Sprintf("(Expected : %d)", wantRoutes)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\t\tAggregated %s Metrics (OTG gNMI)\n%s\n", family, border)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v\n", "Counter", "Sent (out)", "Received (in)")
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v\n", "Opens", c.OutOpens, c.InOpens)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v\n", "Keepalives", c.OutKeepalives, c.InKeepalives)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v\n", "Updates", c.OutUpdates, c.InUpdates)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v  (Expected : 0/0)\n", "Notifications", c.OutNotifications, c.InNotifications)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v  %s\n", "Routes", c.OutRoutes, c.InRoutes, routeExp)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v  (Expected : 0/0)\n", "Route Withdraws", c.OutRouteWithdraw, c.InRouteWithdraw)
	fmt.Fprintf(&b, "\t\t%-26v %-14v %-14v\n", "End-Of-RIB", "-", c.InEndOfRib)
	fmt.Fprintf(&b, "%s\n", border)
	fmt.Fprintf(&b, "\t\t%-26v %-14v (Expected : %d)\n", "Peers Reporting Counters", c.Peers, wantPeers)
	fmt.Fprintf(&b, "\t\t%-26v %-14v (Expected : %d)\n", "Peers That Sent An Open", c.PeersWithOpens, wantPeers)
	fmt.Fprintf(&b, "\t\t%-26v %-14v (Expected : %d)\n", "Peers Exchanging Keepalive", c.PeersWithKeepalives, wantPeers)
	fmt.Fprintf(&b, "\t\t%-26v %-14v (Expected : 0)\n", "Flap Count", c.Flaps)
	fmt.Fprintf(&b, "%s\n", border)
	return b.String()
}

func (c *BGPCounterSum) add(v *otgtelemetry.BgpPeer_Counters) {
	if v == nil {
		return
	}
	c.Peers++
	c.Flaps += v.GetFlaps()
	c.InOpens += v.GetInOpens()
	c.OutOpens += v.GetOutOpens()
	c.InKeepalives += v.GetInKeepalives()
	c.OutKeepalives += v.GetOutKeepalives()
	c.InUpdates += v.GetInUpdates()
	c.OutUpdates += v.GetOutUpdates()
	c.InNotifications += v.GetInNotifications()
	c.OutNotifications += v.GetOutNotifications()
	c.InRoutes += v.GetInRoutes()
	c.OutRoutes += v.GetOutRoutes()
	c.InRouteWithdraw += v.GetInRouteWithdraw()
	c.OutRouteWithdraw += v.GetOutRouteWithdraw()
	c.InEndOfRib += v.GetInEndOfRib()
	if v.GetOutOpens() > 0 {
		c.PeersWithOpens++
	}
	if v.GetInKeepalives() > 0 || v.GetOutKeepalives() > 0 {
		c.PeersWithKeepalives++
	}
}

// BGPCounters reads and sums the peer counters of every configured peer.
func BGPCounters(t *testing.T, otgDev *otg.OTG, peers []string) BGPCounterSum {
	t.Helper()
	var sum BGPCounterSum

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

// LogPortAndARPState logs port link state and, for a sample of devices, whether
// the BGP peer address (== the gateway) resolved via ARP. A session stuck below
// ESTABLISHED with an unresolved gateway is an addressing/link problem, not BGP.
// Only a sample is looked up: the lookup blocks, and there may be tens of
// thousands of devices.
func LogPortAndARPState(t *testing.T, otgDev *otg.OTG, config gosnappi.Config, sample int) {
	t.Helper()
	defer trackPortStateFetch(t, time.Now())
	logPortLinks(t, otgDev, config)
	n := 0
	for _, d := range config.Devices().Items() {
		if n >= sample {
			return
		}
		for _, eth := range d.Ethernets().Items() {
			for _, ip := range eth.Ipv4Addresses().Items() {
				gw := ip.Gateway()
				mac, ok := gnmi.Lookup(t, otgDev, gnmi.OTG().Interface(eth.Name()).Ipv4Neighbor(gw).LinkLayerAddress().State()).Val()
				if ok {
					t.Logf("device %s: %s -> gateway %s resolved to %s", d.Name(), ip.Address(), gw, mac)
				} else {
					t.Logf("device %s: %s -> gateway %s NOT resolved (no ARP entry)", d.Name(), ip.Address(), gw)
				}
			}
		}
		n++
	}
}

// LogPortAndNDState is LogPortAndARPState for IPv6 neighbor discovery.
func LogPortAndNDState(t *testing.T, otgDev *otg.OTG, config gosnappi.Config, sample int) {
	t.Helper()
	defer trackPortStateFetch(t, time.Now())
	logPortLinks(t, otgDev, config)
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

// logPortLinks logs the link state of every port in the config, as OTG gNMI
// reports it.
func logPortLinks(t *testing.T, otgDev *otg.OTG, config gosnappi.Config) {
	for _, p := range config.Ports().Items() {
		if v, ok := gnmi.Lookup(t, otgDev, gnmi.OTG().Port(p.Name()).Link().State()).Val(); ok {
			t.Logf("port %s link (as reported by OTG gNMI): %s", p.Name(), v.String())
		} else {
			t.Logf("port %s link: no state reported", p.Name())
		}
	}
}

func trackPortStateFetch(t *testing.T, start time.Time) {
	t.Logf("GetMetrics: port / neighbor state took %v",
		APITime.Track(APIGetPortState, start).Round(time.Millisecond))
}

// PollInterval scales the telemetry poll interval with the number of peers so
// that polling does not dominate the gNMI server at high scale.
func PollInterval(peers int) time.Duration {
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

// AdaptivePollInterval shortens the interval as sessions come up, so that the
// last few sessions are detected quickly.
func AdaptivePollInterval(base time.Duration, up, want int) time.Duration {
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
