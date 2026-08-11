# BGP B2B Session Scale (OTG-only)

`TestBGPv4B2BScale` and `TestBGPv6B2BScale` bring up N BGP sessions per port between two
ATE ports wired back-to-back (no DUT), verify session state and route exchange over OTG
gNMI telemetry, and run a capped set of data-plane flows over the advertised routes as a
sanity check.


```
bgp_b2b_scale/
├── README.md          this file, covers both tests
├── card_limits.json   the rating matrix, shared by both (optional; see Card limits)
├── bgpv4/
│   └── bgpv4_b2b_scale_test.go    TestBGPv4B2BScale, package otg_b2b_bgp_scale
└── bgpv6/
    └── bgpv6_b2b_scale_test.go    TestBGPv6B2BScale, package otg_b2b_bgpv6_scale

../scale/              package scale — the shared library both tests import
├── chassis.go         chassis / card / resource-group discovery, port + chassis health
├── limits.go          the rating matrix, card_limits.json, the limit warnings
├── ports.go           ports-only seed config, port reboot
├── timing.go          API call timing and the per-iteration table
├── addressing.go      per-session address, MAC and VLAN arithmetic
├── bgpconfig.go       one BGP device / one flow, per address family
├── bgptelemetry.go    session-state and peer-counter fetch + aggregation
└── traffic.go         flow counter fetch, the "all flows stopped" wait
```

**The split between the two.** A test keeps its outline and its assertions; the library
takes the mechanics. Reading either test file alone still tells you which ports it uses,
how many sessions and routes it asks for, what goes on each device, what it polls and what
it treats as a pass. What it no longer contains is *how* any of that is done. The library
decides nothing: the limit checks warn and let the run proceed at exactly the scale asked
for, and the telemetry helpers fetch and aggregate but never judge.

The tests were previously one self-contained file each, at the cost of ~1900 duplicated
lines. They now depend on the featureprofiles module and can no longer be handed out as a
lone `.go` file. Everything about running them is unchanged, including the single-file
`go test <file>.go` form.

Unless stated otherwise, everything below applies to both. The v4/v6 differences are
addressing (`/24` + `/32` routes vs `/64` + `/128`), and that a v6 peer cannot use its
interface address as a router ID — the v6 test derives one from `-scale_p1_router_id` /
`-scale_p2_router_id` instead.

## Topology

```
        ATE port1  <------ b2b cable ------>  ATE port2
   N devices, 1 BGPv4 peer each          N devices, 1 BGPv4 peer each
```

Every port1 device is paired with exactly one port2 device, and the two peer with each
other. Total peers = `2 x N`.

Addressing (all flag-driven, defaults shown):

| Item | port1 device *i* | port2 device *i* |
| --- | --- | --- |
| Session subnet | `18.0.0.0 + i*256`, i.e. session 1 = `18.0.1.0/24` | same subnet as port1 device *i* |
| Interface IPv4 | `.1` of the session subnet | `.2` of the session subnet |
| Prefix | `/24` | `/24` |
| Gateway / BGP peer address | the paired port2 address | the paired port1 address |
| MAC | `02:00:01:00:00:01 + (i-1)` | `02:00:02:00:00:01 + (i-1)` |
| Router ID | own interface IPv4 | own interface IPv4 |
| VLAN (inner dot1q) | `i` (wraps at 4095) | same as port1 device *i* |
| VLAN (outer QinQ) | `1 + (i-1)/4095` | same as port1 device *i* |
| Advertised route range | `100.0.0.1 + routes*(i-1)`, /32 | `200.0.0.1 + routes*(i-1)`, /32 |

Both sides advertise, so every peer both sends and receives `-scale_routes` routes.
**All peers are iBGP in a single AS** (`-scale_as`, default 65000).

Every device is double tagged with the same scheme as the Athena scale test
(`scale.GenerateVlanIds`): the tag pair depends only on the session index, so the two
devices of a pair share it and each session pair sits in its own broadcast domain.
Device MTU is 1500 and the port L1 MTU is raised to 1516 (`-scale_l1_mtu`) to carry the
two 4-byte tags. The flows carry the same tags on their transmitted frames. Tagging can
be turned off with `-scale_vlan=false` (or reduced to a single tag with
`-scale_qinq=false`).

**One subnet per session pair is required, not cosmetic.** ixia-c answers ARP for a
subnet from a single device on the port. When all devices shared one flat `/16`, every
port1 device's gateway resolved to *p2dev1's* MAC — harmless while untagged, but once
each pair is in its own VLAN that reply is dropped as wrong-VLAN by every device except
the first, no neighbor entry is ever published, and `start flows` fails with
`Unable to resolve the destination MAC address for this 'p1rrN' interface`. Per-pair
`/24`s (the Athena scale test's scheme) put the answering device in the right VLAN. The
flows additionally set the dst MAC explicitly instead of relying on auto-resolution.

`18.0.0.0/8` gives 65535 per-session `/24`s, well past the 36000 sessions/port tried
here.

## Prerequisites

- An Ixia-C controller reachable at the `otg`/`gnmi` targets in the binding (default
  `127.0.0.1:40051` / `127.0.0.1:50051`).
- The two ATE ports in the binding wired back-to-back.

Binding and testbed used by both tests:

- [../otgb2b-hw.binding](../otgb2b-hw.binding) — Ixia-C controller + the two physical
  port names. **Edit the `ports { name: ... }` entries to match your chassis/card/port.**
- [../otgb2b-hw.testbed](../otgb2b-hw.testbed) — abstract `ate` with `port1`, `port2`
  and the link between them.

## How to run

From inside `featureprofiles/`:

```sh
cd /home/azhar/fp/featuresprofile-ci/featureprofiles
B=/home/azhar/fp/featuresprofile-ci/featureprofiles/feature/experimental/otg_only

# BGPv4
go test -v ./feature/experimental/otg_only/bgp_b2b_scale/bgpv4/bgpv4_b2b_scale_test.go -timeout 60m \
  -binding $B/otgb2b-hw.binding -testbed $B/otgb2b-hw.testbed \
  -scale_sessions=10 | tee bgpv4_b2b_scale_10.log

# BGPv6
go test -v ./feature/experimental/otg_only/bgp_b2b_scale/bgpv6/bgpv6_b2b_scale_test.go -timeout 60m \
  -binding $B/otgb2b-hw.binding -testbed $B/otgb2b-hw.testbed \
  -scale_sessions=10 | tee bgpv6_b2b_scale_10.log
```

Scale ladder — same command, only `-scale_sessions` changes:

```sh
-scale_sessions=10                          # 20 peers
-scale_sessions=100                         # 200 peers
-scale_sessions=1000    -timeout 120m       # 2000 peers
-scale_sessions=10000   -timeout 180m       # 20000 peers
```

`-timeout` is the **go test** timeout and must be larger than the sum of the test's own
waits. The in-test waits already default high (`-scale_session_timeout=30m`,
`-scale_traffic_timeout=60m`), so raise `-timeout` when you go past a few thousand
sessions.

Control-plane only (fastest way to push session scale, skips all flows):

```sh
  -scale_sessions=10000 -scale_traffic=false -timeout 180m
```

Sessions plus routes at scale (10 routes per peer = 200000 routes at 10000 sessions):

```sh
  -scale_sessions=10000 -scale_routes=10 -scale_traffic=false -timeout 180m
```

Soak / repeatability — repeat push → sessions up → traffic N times, timing each pass:

```sh
  -scale_sessions=100 -scale_iterations=10 -timeout 120m
```

## Flags

Scale and workload:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-scale_sessions` | `10` | BGPv4 sessions **per port**; total peers = 2x this |
| `-scale_routes` | `1` | /32 routes advertised by each peer; `0` = sessions only, no route ranges and no flows |
| `-scale_iterations` | `1` | Times to repeat push → sessions up → traffic |

Timeouts (in-test waits, all failures are reported, never silently skipped):

| Flag | Default | Meaning |
| --- | --- | --- |
| `-scale_session_timeout` | `30m` | Max wait for **all** peers to reach ESTABLISHED |
| `-scale_metrics_timeout` | `5m` | Max wait for BGP route counters to settle |
| `-scale_traffic_timeout` | `60m` | Max wait for every flow to finish transmitting its packet count |

Data plane:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-scale_traffic` | `true` | Run the data-plane sanity-check flows |
| `-scale_max_flows` | `256` | Cap on flow count — **256 is the AresOne card limit**. One flow per session pair, so flows = `min(sessions, this)` |
| `-scale_flow_packets` | `1000` | Fixed packet count per flow |
| `-scale_flow_pps` | `500` | Rate per flow |
| `-scale_flow_size` | `100` | Frame size |

Addressing and BGP:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-scale_subnet_base` | `18.0.0.0` | Base of the per-session `/24`s; session *i* uses `base + i*256`, `.1` on port1 and `.2` on port2 |
| `-scale_ip_prefix` | `24` | Prefix length of the per-session subnets |
| `-scale_as` | `65000` | AS number — every peer is iBGP in this single AS |

Encapsulation:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-scale_vlan` | `true` | Tag every device with a per-session dot1q VLAN |
| `-scale_qinq` | `true` | Add the outer QinQ tag as well (needs `-scale_vlan`) |
| `-scale_l1_mtu` | `1516` | Port layer1 MTU; the default carries both tags on top of the 1500 byte device MTU |

Optional non-default BGP TCP ports (both must be set to take effect; port2 peers get the
pair swapped, so what port1 listens on is what port2 connects to):

| Flag | Default | Meaning |
| --- | --- | --- |
| `-scale_listen_port` | `0` | Listen port on port1 peers (`0` = keep 179) |
| `-scale_neighbor_port` | `0` | Neighbor port on port1 peers (`0` = keep 179) |

Debug:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-scale_wildcard_telemetry` | `true` | Fetch peer telemetry with one wildcard `BgpPeerAny()` query per poll. Set `false` to force per-peer queries (much slower at scale, useful to cross-check the wildcard) |
| `-scale_dump_config` | `false` | Log the pushed OTG config as JSON |

Chassis / card discovery. These are defined by `../scale`, not by the tests — along with
`-scale_wildcard_telemetry` above, they are the flags describing how to reach the rig and
how to read telemetry. Every other flag on this page belongs to the test, which is what
decides the scale and shape of a run.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-scale_chassis_check` | `false` | Discover the Ixia card behind the bound ports and warn when the requested scale exceeds its rated session / flow limits |
| `-scale_chassis_user` | `admin` | IxOS chassis username |
| `-scale_chassis_pass` | `admin` | IxOS chassis password |
| `-scale_chassis_timeout` | `30s` | Per-request timeout for the chassis SSH / REST calls |
| `-scale_limits_file` | *(auto)* | Path to a `card_limits.json` overriding the built-in rating matrix. Default: `card_limits.json` next to the test, then in its parent directory |
| `-scale_port_reboot_timeout` | `10m` | Max wait for the ports to come back after a reboot |

## Port reboot

`-scale_port_reboot=true` reboots the ports under test **once at the start of the run,
before `SetConfig`**, and waits for their PCPUs to report `PCPUREADY` again. It exists so
a measurement can start from a known port state instead of inheriting whatever the
previous run left on the port.

```sh
go test -v ./feature/experimental/otg_only/bgp_b2b_scale/bgpv4/bgpv4_b2b_scale_test.go -timeout 90m \
  -binding $B/otgb2b-hw.binding -testbed $B/otgb2b-hw.testbed \
  -scale_port_reboot=true -scale_sessions=36000 ...
```

```
rebooting port ares1-...;1;9 (REST id 1094)...
rebooting port ares1-...;1;10 (REST id 1095)...
[t+25s   ] ports back after reboot: 0/2 (…;1;9=absent, …;1;10=absent)
[t+1m15s ] ports back after reboot: 2/2 (…;1;9=PCPUREADY/UP, …;1;10=PCPUREADY/UP)
port reboot complete in 1m15s
```

- It is **off by default** because it costs minutes on every run. Turn it on for a scale
  ladder, or when chasing a regression where the previous run's residue is a plausible
  cause.
- It goes over `POST /chassis/api/v2/ixos/ports/<id>/operations/reboot`, keyed by the
  port's **REST resource id** (not its card/port number), which the test reads from the
  chassis port list during discovery.
- It therefore **needs the REST API**. A chassis still on a default password refuses to
  issue an API session (`resetWeakPassword`) and cannot use this — discovery and card
  limits still work there over SSH, only the reboot does not.
- Failures are **fatal**. The reboot was asked for explicitly; quietly carrying on with
  un-rebooted ports would answer a different question than the one being asked.
- Rebooting can drop the port's ownership. `PushConfig` re-takes it, so the run continues,
  but anything else holding those ports will lose them.

## Card limits

The scale a rig can carry depends on the card behind the bound ports **and on how that
card's resource groups are broken out** — not on the card model alone. Before pushing
anything, the test reads `show topology` over SSH from the chassis named in the binding
port (`<chassis>;<card>;<port>`), finds the resource group that owns each port, and looks
up the rating for that card in that mode.

| Card / mode | BGPv4 | BGPv6 |
| --- | --- | --- |
| AresONE, group split `1x800G` | 36556 | 26982 |
| AresONE, group split `2x400G` | 18278 | 13491 |
| AresONE, group split `4x200G` | 9139 | 6746 |
| AresONE, group split `8x100G` | 4570 | 3373 |
| AresONE, group split `16x50G` | 2285 | 1686 |
| NOVUS10/1GE/100M, normal mode | 36556 | 26982 |
| NOVUS10/1GE/100M, aggregated mode | 60928 | 60928 |
| NOVUS10/1GE32S | 17843 | 15667 |
| SERT 100G (100GE-QSFP28) | 4461 | 3373 |

An AresONE resource group is rated for 36556 / 26982 sessions in total, split evenly over
however many ports the group is broken out into — which is why the rows halve as the port
count doubles.

Flow ratings: **AresONE 256**, **NOVUS10/1GE/100M 512** (the whole family, including
`NOVUS10/1GE32S`). Cards with no published flow rating log as unrated and
`-scale_max_flows` is used as given.

A card with no row is logged as unrated and no limit is applied.

### Where the numbers come from

The matrix is compiled into each test as constants, so a copy of the `.go` file enforces
these ratings on its own. [card_limits.json](card_limits.json) in this directory overrides
them, and both tests pick it up automatically — they look for `card_limits.json` next to
the test first, then one directory up (which is how the two share this one file).
`-scale_limits_file=<path>` names a different one.

Because the enforced number is no longer implied by the test's version alone, every run
logs which table it used:

```
		rating matrix   : /path/to/bgp_b2b_scale/card_limits.json
```

and, when the file actually changes something, exactly what it changed:

```
		Card limits overridden by /path/to/bgp_b2b_scale/card_limits.json
------------------------------------------------------------------------------
		aresone: 36556/26982 sessions, 300 flows (built-in: 36556/26982, 256)
------------------------------------------------------------------------------
```

Rules worth knowing:

- **A file that exists but does not parse is a fatal error**, not a silent fall back to
  the built-ins. It was put there deliberately; enforcing a different number than the one
  someone wrote down is the worse failure. Delete the file to use the built-in table.
- **Fields are optional per row** — omit one and the built-in value is kept, so you can
  correct a single number without restating the row.
- **`0` is not "omitted"**. It means *not rated*, which disables that check and lets
  `-scale_sessions` / `-scale_max_flows` through unchecked.
- `rows.aresone` is a whole-resource-group total, split over the group's port count.
  Every other row is a flat per-port figure.
- `cards` rates a card the built-in matching rules do not cover: `match` is a
  case-insensitive substring of the card type from `show topology`, and the first match
  wins over every built-in rule. Set `per_group: true` for a whole-group total.

**Requesting more than the rated scale is a warning, not a failure.** The run goes ahead
at exactly the scale asked for — the scale is never silently clamped, since that would
report a pass for a scale that was never reached. The warning is boxed in the log where it
is raised and repeated in a summary at the end of the run:

```
******************************************************************************
*** WARNING: -scale_sessions=36000 exceeds the 18278 BGPv4 sessions/port this card is
    rated for (AresONE S400GD-16P-QDD, 2x400GBASE-CR8: 36556/26982 per group split 2 ways)
******************************************************************************
```

Two caveats worth knowing:

- The rating is **per port**. A back-to-back pair usually sits in one resource group
  (AresONE ports 9 and 10 are both RG05), so that group carries the sum of the two sides;
  the test logs a warning when it detects this.
- IxOS exposes **no per-port CPU** figure over its REST API, only the PCPU readiness
  state. Per-port memory and PCPU status are logged per port, and the chassis-wide CPU and
  memory counters are logged as the closest available proxy. A chassis still on a default
  password refuses to issue a REST session at all (`resetWeakPassword`); discovery still
  works there over SSH, and only the health figures are missing.

## What the test verifies

1. **Card rating** — resolves the bound ports to a card and resource group and warns
   before pushing if the requested sessions or flows exceed what that card is rated for.
2. **Sessions up** — polls until every peer reports `ESTABLISHED`. Fails on timeout.
3. **Route exchange** — polls the aggregated peer counters until
   `routes received == routes advertised == 2 * sessions * routes`, with zero route
   withdraws. Fails on any session flap.
4. **Data plane** — starts the flows, waits until **every** flow reports
   `transmit == false` and has sent its full packet count, then stops traffic and checks
   per-flow that tx equals the expected packet count and rx matches tx (tolerance: 50
   packets / 2%). Also fails if aggregate tx != rx.

## Reading the output

Session progress prints a state histogram plus a sample of peers that are not up yet:

```
[t+4s    ] BGPv4 sessions ESTABLISHED: 2/20 | GetMetrics: state 71ms, counters 68ms | states: ESTABLISHED=2 IDLE=18
	not ESTABLISHED (sample): p1peer10=IDLE, p1peer2=IDLE, ...
```

Every poll also prints the aggregated counters, so you can see exactly how far the
handshake got — this is the fastest way to tell "BGP never started" from "BGP started
and failed":

```
		Counter                    Sent (out)     Received (in)
		Opens                      20             20
		Keepalives                 40             40
		Updates                    20             20
		Notifications              0              0               (Expected : 0/0)
		Routes                     20             20              (Expected : 20)
		Route Withdraws            0              0               (Expected : 0/0)
		End-Of-RIB                 -              0
------------------------------------------------------------------------------
		Peers Reporting Counters   20             (Expected : 20)
		Peers That Sent An Open    20             (Expected : 20)
		Peers Exchanging Keepalive 20             (Expected : 20)
		Flap Count                 0              (Expected : 0)
```

- `Peers Reporting Counters` at the expected value but `Peers That Sent An Open` at `0`
  means the peers never even tried to connect — look at addressing/ARP, not at BGP.
- `Notifications` sent > 0 with sessions still coming up is usually BGP connection
  collision resolution during simultaneous open; harmless if it does not persist.

Before waiting, the test logs port link state and per-device gateway ARP resolution:

```
device p1dev1: 18.0.1.1 -> gateway 18.0.1.2 resolved to 02:00:02:00:00:01
```

Traffic progress and the final summary:

```
[t+7s    ] flows finished transmitting: 100/100 (still transmitting: 0, below 1000 packets: 0, tx on pending flows: 100000) | GetMetrics: 100 flows in 412ms
Traffic summary over 100 flows: tx 100000 (expected 100000), rx 100000, loss 0.00%, flows short on tx 0, lossy flows 0 | GetMetrics: 100 flows in 398ms
```

### API timings

Every OTG API call is timed. One-shot calls are highlighted as they happen — grep
`>>> OTG API` to pull just these out of a run log:

```
>>> OTG API | PushConfig [SetConfig]                          1m2.313s
>>> OTG API | StartProtocols                                    4.201s
>>> OTG API | StartTraffic [SetTransmitState:start]             1.884s
>>> OTG API | StopTraffic [SetTransmitState:stop]                 912ms
>>> OTG API | StopProtocols                                      3.774s
```

The `GetMetrics` fetches behind the poll loops are timed per poll (shown inline on the
poll's own log line, above) and aggregated. Each iteration ends with the full table, which
is where a scale run's wall clock is accounted for:

```
		OTG API call timings (iteration 1/1, 100 sessions/port)
----------------------------------------------------------------------------------------------------
		API call                                calls          total            avg            min            max
		GetMetrics: port / neighbor state           1          142ms          142ms          142ms          142ms
		PushConfig [SetConfig]                      1       1m2.313s       1m2.313s       1m2.313s       1m2.313s
		StartProtocols                              1         4.201s         4.201s         4.201s         4.201s
		GetMetrics: BGP session state               3          213ms           71ms           64ms           83ms
		GetMetrics: BGP peer counters               4          281ms           70ms           62ms           79ms
		StartTraffic [SetTransmitState:start]       1         1.884s         1.884s         1.884s         1.884s
		GetMetrics: flow metrics                    5         2.104s          420ms          389ms          467ms
		StopTraffic [SetTransmitState:stop]         1          912ms          912ms          912ms          912ms
		StopProtocols                               1         3.774s         3.774s         3.774s         3.774s
----------------------------------------------------------------------------------------------------
		total time in OTG API calls                        1m15.824s
----------------------------------------------------------------------------------------------------
```

Rows appear in the order each call was first made, and the table is reset per iteration.

## Observed results

Measured on an AresONE b2b setup:

| Sessions/port | Peers | Time to all ESTABLISHED | Traffic |
| --- | --- | --- | --- |
| 2 | 4 | ~4 s | not run |
| 10 | 20 | ~6 s | 10 flows, 0.00% loss |
| 100 | 200 | ~6 s | 100 flows, 0.00% loss |

1000 and 10000 have not been characterised here yet — record them as you run them.

## Gotchas

- **Give every session pair its own subnet.** Sharing one subnet across all devices
  breaks the data plane once VLANs are on (see the addressing section above): BGP still
  comes up, but `start flows` cannot resolve a dst MAC for any session past the first.
  A flat `10.0.0.0/8` was also observed to leave every peer in `IDLE`, sending no opens
  at all.
- **Flows are capped at 256 by default** because that is the AresOne card limit (Novus 10G
  is rated for 512), and ixia-c allows only one tx device per flow so the count cannot be
  collapsed. Above the cap the extra sessions are verified by BGP telemetry only — the
  flows are a data-plane sanity check, not full coverage. The cap is checked against the
  discovered card (see [Card limits](#card-limits)); a request above the card's rating
  warns and runs anyway.
- **Port link state reads `DOWN`** over ixia-c gNMI for Ixia HW ports even while the
  port is up and passing traffic. It is logged as informational only; ignore it.
- **Flow-name wildcards** (`gnmi.OTG().FlowAny()...`) are not reliably served by the
  ixia-c gNMI server on these testbeds, so all flow telemetry uses concrete per-flow
  queries. BGP peer wildcards (`BgpPeerAny()`) *are* served and are used to keep polling
  cheap at scale; the test falls back to per-peer queries automatically if a wildcard
  query returns nothing.
- **Poll intervals scale with peer count** (2s at <=100 peers up to 30s above 10000) and
  tighten as sessions come up, so telemetry polling does not swamp the gNMI server at
  high scale.
- Real-hardware runs are slow (`PushConfig` reboots ports); always tee to a log file.
