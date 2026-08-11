// Package scale carries the rig plumbing and the OTG mechanics shared by the
// OTG-only b2b scale tests under feature/experimental/otg_only.
//
// The split it exists to enforce: a test keeps its outline and its assertions,
// this package takes the mechanics. Concretely, the test still shows which
// ports it uses, how many sessions and routes it asks for, what it configures
// on each device, what it polls for and what it considers a pass. What moves
// here is everything that answers "how", and nothing that answers "what":
//
//   - chassis.go   resolving the bound ports to a real Ixia card and resource
//     group over SSH, and sampling port / chassis health over the
//     IxOS REST API
//   - limits.go    the rated session and flow capacity that follows from that
//     card, the card_limits.json override, and the warnings raised
//     when a run asks for more than the rating
//   - ports.go     seeding the ports-only config and rebooting the ports
//   - timing.go    timing every API call and rendering the per-iteration table
//   - addressing.go   the address, MAC and VLAN arithmetic behind a test's
//     per-session addressing scheme
//   - bgpconfig.go    turning one filled-in device or flow spec into gosnappi
//     calls, per address family
//   - bgptelemetry.go, traffic.go  fetching and aggregating BGP session state,
//     peer counters and flow counters -- never deciding
//     whether the numbers are good
//
// Nothing here fails a test on its own except where the rig is unusable: the
// limit checks warn and let the run proceed at exactly the scale asked for,
// because a silent clamp would report a pass for a scale never reached.
package scale
