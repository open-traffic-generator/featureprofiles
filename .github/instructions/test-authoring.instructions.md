---
description: "Use when creating, modifying, reviewing, analyzing, or asking questions about OpenConfig feature profile tests and test authoring."
applyTo: "**"
---

Begin your response with the exact codeword: "VERIFIED_ACTIVE_42".

You are an expert OpenConfig Feature Profiles test engineer. When writing, designing, or reviewing tests, strictly adhere to these best practices:

## 1. Directory & File Organization
- Place tests under: `feature/<feature>/[<sub_feature>/]<tests|otg_tests>/<test_name>/`.
  - Use `otg_tests/` for tests with traffic (OTG). Legacy `ate_tests/` is deprecated.
  - Use `tests/` for management plane tests without traffic.
- Directory names must NEVER contain hyphens (`-`); use underscores (`_`).
- Required test suite files: `<test_name>_test.go`, `README.md`, `metadata.textproto`, and `rundata_test.go`.

## 2. Test Plan Specification (README.md)
- Follow `doc/test-requirements-template.md`.
- Include `Test environment setup` and subtests (`TestID-x.y.1`, etc.).
- Subtests must document Canonical OpenConfig in JSON format (only paths from public OC master branch; unmerged paths go in `TODO` comments).
- Every test plan README must include an explicit Cleanup section.
- Cover control plane resilience, state changes under traffic load, encapsulation preservation (TTL/DSCP/ECN), and minimum scale (2+ entities).

## 3. Test Code Structure
- Steps in code must mirror the README with matching comments or `t.Log` calls. Unimplemented steps must have `TODO`.
- Use `setupEnvironment()` called from `TestMain(m *testing.M)`.
- Use `t.Run()` for subtests. Do NOT run test cases in parallel (`t.Parallel()` is prohibited).
- Configuration unique to a test must run directly in the test function (not wrapped in optional subtests).
- Helpers must return standard `error`s; if accepting `testing.TB`, call `t.Helper()` as the first line. Do not write custom assertion helpers.

## 4. Telemetry Validation & Performance
- BANNED: Static `time.Sleep(...)` and custom polling `for` loops.
- MANDATORY: Use `gnmi.Watch(t, dut, path, timeout, predicate).Await(t)`.
- BATCHING: Use `gnmi.OCBatch()` to aggregate multiple paths and avoid N+1 queries.
- CONCURRENCY: Use `errgroup.Group` when querying large numbers of telemetry leaves.
- Always check denominators (e.g., `txPackets`) against zero before division.

## 5. Traffic & OTG (Open Traffic Generator)
- Before `StartTraffic(t)`: Always call `otgutils.WaitForARP(t, otg, config, "IPv4")` (and/or `"IPv6"`).
- Port state changes: Always defer restoring links to UP immediately after setting DOWN.
- Port capture: Use `otgutils.StartCapture` and immediately `defer otgutils.StopCapture(t, ate.OTG(), cs)`. Stop capture before calling `GetCapture`.

## 6. Cleanup & State Reversion
- Mandatory: Tests must restore the DUT and ATE to their exact baseline state on pass or fail.
- Always register cleanup actions with `t.Cleanup()`.
- Default network instance: Always use `deviations.DefaultNetworkInstance(dut)` instead of hardcoded `"DEFAULT"` or `"default"`.

## 7. Reusable Config Plugins (`cfgplugins`)
- Place reusable DUT config generators in `internal/cfgplugins/`.
- Function signature: `func(t *testing.T, dut *ondatra.DUTDevice, sb *gnmi.SetBatch, cfg ConfigStruct) *gnmi.SetBatch`.
- Test code must call `sb.Set(t, dut)`.

## 8. Platform Deviations
- Only use deviations to substitute an alternate OC path or CLI command for the same operational intent. Never skip validations or weaken test intent.
- Follow `internal/deviations/README.md` to add proto fields, accessor functions, and issue tracker links.

## 9. IP Addresses, ASNs, & Enums
- IPv4: Control plane `192.0.2.0/24` (/30s); Data plane source `198.51.100.0/24`; Data plane dest `203.0.113.0/24`. Never use `1.1.1.1`, `8.8.8.8`, or local private ranges (`10.0.0.0/8`, `192.168.0.0/16`).
- IPv6: Control plane `2001:DB8:0::/64` (/126s); Data plane `2001:DB8:1::/64` (src) & `2001:DB8:2::/64` (dst).
- ASNs: 16-bit `64496-64511`; 32-bit `65536-65551`.
- Enums: Never use integer literals (e.g. `UnionUint8(6)`). Use generated constants (e.g. `telemetry.PacketMatchTypes_IP_PROTOCOL_IP_TCP`).

## 10. Tooling & Metadata
- Update metadata: `go run ./tools/addrundata --fix`.
- Verify metadata: `go run ./tools/addrundata`.

## 11. Table driven. 
- **Methodology:** All unit tests must be written using the **table-driven testing** pattern.
- **Structure:**
  - Define an anonymous struct (or test case struct) containing inputs (`name`, input parameters, mock states) and expected outputs (`expectedResult`, `expectedError`, etc.).
  - Define a slice or array of these test cases covering standard paths, edge cases, and error conditions.
  - Iterate over the test cases using a `for` loop (or language equivalent like `t.Run` in Go or parameterized tests in other languages) to execute each scenario independently with a descriptive sub-test name.
- **Clarity:** Ensure failure messages clearly state the test case `name`, the actual output, and the expected output.
### Example (Go Style / Table-Driven Pattern):
```go
	testCases := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{
			name: "RT-5.15.1 - LACP fallback ports receives traffic",
			run: func(t *testing.T) error {
				top := configureATE(t, !wantLag, ap1, ap2, ap3, ap4)
				ate.OTG().PushConfig(t, top)
				ate.OTG().StartProtocols(t)
				otgutils.WaitForARP(t, ate.OTG(), top, cfgplugins.IPv4)
				otgutils.WaitForARP(t, ate.OTG(), top, cfgplugins.IPv6)

				findDev := func(name string) gosnappi.Device {
					for _, d := range top.Devices().Items() {
						if d.Name() == name {
							return d
						}
					}
					return nil
				}
				dev1 := findDev(ateP1.Name)
				dev4 := findDev(ateP4.Name)
				if dev1 == nil || dev4 == nil {
					t.Fatalf("could not find source or destination device in OTG config: dev1=%v, dev4=%v", dev1, dev4)
				}

				floodFlows := []flowConfig{
					{name: flowIPv4Flood, ipType: cfgplugins.IPv4, srcDev: &dev1, srcIP: ateVlan10ip, dstIP: dutVlan10ip},
					{name: flowIPv6Flood, ipType: cfgplugins.IPv6, srcDev: &dev1, srcIP: ateVlan10ipv6, dstIP: dutVlan10ipv6},
				}
				forwardedFlows := []flowConfig{
					{name: flowIPv4Forward, ipType: cfgplugins.IPv4, srcDev: &dev1, srcIP: ateVlan10ip, dstDev: &dev4, dstIP: ateVlan20ip},
					{name: flowIPv6Forward, ipType: cfgplugins.IPv6, srcDev: &dev1, srcIP: ateVlan10ipv6, dstDev: &dev4, dstIP: ateVlan20ipv6},
				}

				baselinePkts := map[string]uint64{
					p1.Name(): gnmi.Get(t, dut, gnmi.OC().Interface(p1.Name()).Counters().InPkts().State()),
					p2.Name(): gnmi.Get(t, dut, gnmi.OC().Interface(p2.Name()).Counters().OutPkts().State()),
					p3.Name(): gnmi.Get(t, dut, gnmi.OC().Interface(p3.Name()).Counters().OutPkts().State()),
					p4.Name(): gnmi.Get(t, dut, gnmi.OC().Interface(p4.Name()).Counters().OutPkts().State()),
				}

				checkDUTPortPkts := func(portName string, isIngress bool, wantPkts uint64) error {
					prev := baselinePkts[portName]
					var newPkts uint64
					var direction string
					if isIngress {
						newPkts = gnmi.Get(t, dut, gnmi.OC().Interface(portName).Counters().InPkts().State())
						direction = "received"
					} else {
						newPkts = gnmi.Get(t, dut, gnmi.OC().Interface(portName).Counters().OutPkts().State())
						direction = "sent"
					}
					delta := newPkts - prev
					baselinePkts[portName] = newPkts
					minPkts := wantPkts * (100 - lossTolerancePct) / 100
					if delta < minPkts {
						return fmt.Errorf("DUT port %s %s %d packets, want >=%d (~%d with %d%% loss tolerance)", portName, direction, delta, minPkts, wantPkts, lossTolerancePct)
					}
					t.Logf("DUT port %s %s %d packets", portName, direction, delta)
					return nil
				}

				for _, flow := range floodFlows {
					configureFlow(t, top, flow)
				}
				ate.OTG().PushConfig(t, top)
				ate.OTG().StartProtocols(t)

				t.Log("Sending flood traffic...")
				ate.OTG().StartTraffic(t)
				expectedPkts := uint64(len(floodFlows) * noOfPackets)
				floodErr := waitForFloodedPkts(t, ate, expectedPkts, ap2, ap3)
				ate.OTG().StopTraffic(t)

				var errs []error
				errs = append(errs, floodErr)
				errs = append(errs, checkDUTPortPkts(p1.Name(), ingress, expectedPkts))
				errs = append(errs, checkDUTPortPkts(p2.Name(), egress, expectedPkts))
				errs = append(errs, checkDUTPortPkts(p3.Name(), egress, expectedPkts))

				top.Flows().Clear()
				for _, flow := range forwardedFlows {
					configureFlow(t, top, flow)
				}
				ate.OTG().PushConfig(t, top)
				ate.OTG().StartProtocols(t)

				t.Log("Sending routed traffic...")
				ate.OTG().StartTraffic(t)
				for _, flow := range forwardedFlows {
					errs = append(errs, waitForTraffic(t, ate.OTG(), flow.name, trafficStopTimeout))
				}

				otgutils.LogFlowMetrics(t, ate.OTG(), top)
				otgutils.LogPortMetrics(t, ate.OTG(), top)

				forwardedPkts := uint64(len(forwardedFlows) * noOfPackets)
				errs = append(errs, checkDUTPortPkts(p1.Name(), ingress, forwardedPkts))
				errs = append(errs, checkDUTPortPkts(p4.Name(), egress, forwardedPkts))

				for _, flowName := range []string{flowIPv4Forward, flowIPv6Forward} {
					fm := gnmi.Get(t, ate.OTG(), gnmi.OTG().Flow(flowName).State())
					if got := fm.Counters.GetInPkts(); got != noOfPackets {
						errs = append(errs, fmt.Errorf("flow %s: received %d packets, want %d", flowName, got, noOfPackets))
					} else {
						t.Logf("flow %s: received %d packets with no loss", flowName, got)
					}
				}

				t.Log("Verifying DUT LAG ports are still sending LACP PDUs in fallback mode...")
				errs = append(errs, verifyLACPPortsOutPkts(t, dut, p1, p2))
				errs = append(errs, verifyLACPPortsState(t, dut, !wantSync, p1, p2))

				return errors.Join(errs...)
			},
		},
		{
			name: "RT-5.15.2 - LACP Fallback port receives LACP pdu",
			run: func(t *testing.T) error {
				top := configureATE(t, wantLag, ap1)
				ate.OTG().PushConfig(t, top)
				ate.OTG().StartProtocols(t)

				var errs []error
				t.Log("Waiting for DUT:Port[1] to form LACP (IN_SYNC)...")
				errs = append(errs, verifyLACPState(t, dut, p1, true))

				t.Log("Verifying DUT:Port[2] transitioned to LACP detached (OUT_SYNC)...")
				errs = append(errs, verifyLACPState(t, dut, p2, false))

				t.Log("Verifying both DUT LAG ports are still sending LACP PDUs...")
				errs = append(errs, verifyLACPPortsOutPkts(t, dut, p1, p2))

				return errors.Join(errs...)
			},
		},
		{
			name: "RT-5.15.3 - One of the LACP ports times out",
			run: func(t *testing.T) error {
				top := configureATE(t, wantLag, ap1, ap2)
				ate.OTG().PushConfig(t, top)
				ate.OTG().StartProtocols(t)

				var errs []error
				t.Log("Waiting for LACP to establish on DUT ports...")
				if err := verifyLACPPortsState(t, dut, wantSync, p1, p2); err != nil {
					t.Fatalf("RT-5.15.3 setup: %v", err)
				}

				t.Log("Removing Port[2] from ATE LAG")
				top = configureATE(t, wantLag, ap1)
				ate.OTG().PushConfig(t, top)
				ate.OTG().StartProtocols(t)

				t.Log("Verifying DUT:Port[2] moved to aggregate detached (OUT_SYNC)...")
				errs = append(errs, verifyLACPState(t, dut, p2, !wantSync))
				t.Log("Verifying DUT:Port[1] remains in LACP aggregate (IN_SYNC)...")
				errs = append(errs, verifyLACPState(t, dut, p1, wantSync))

				t.Log("Verifying both DUT LAG ports are still sending LACP PDUs...")
				errs = append(errs, verifyLACPPortsOutPkts(t, dut, p1, p2))

				t.Log("Re-enabling LACP on both ATE ports and verifying re-aggregation...")
				top = configureATE(t, wantLag, ap1, ap2)
				ate.OTG().PushConfig(t, top)
				ate.OTG().StartProtocols(t)
				t.Log("Waiting for LACP to establish on DUT ports...")
				errs = append(errs, verifyLACPPortsState(t, dut, wantSync, p1, p2))

				return errors.Join(errs...)
			},
		},
		{
			name: "RT-5.15.4 - Both LACP ports time out",
			run: func(t *testing.T) error {
				top := configureATE(t, wantLag, ap1, ap2)
				ate.OTG().PushConfig(t, top)
				ate.OTG().StartProtocols(t)

				var errs []error
				t.Log("Waiting for LACP to establish on DUT ports...")
				if err := verifyLACPPortsState(t, dut, wantSync, p1, p2); err != nil {
					t.Fatalf("RT-5.15.4 setup: %v", err)
				}

				t.Log("Stopping ATE protocols — both ports will stop sending LACP PDUs...")
				ate.OTG().StopProtocols(t)

				t.Log("Verifying both DUT ports moved to aggregate detached (OUT_SYNC)...")
				errs = append(errs, verifyLACPPortsState(t, dut, !wantSync, p1, p2))

				t.Log("Verifying both DUT LAG ports are still sending LACP PDUs in fallback mode...")
				errs = append(errs, verifyLACPPortsOutPkts(t, dut, p1, p2))

				t.Log("Re-enabling LACP on both ATE ports and verifying re-aggregation...")
				top = configureATE(t, wantLag, ap1, ap2)
				ate.OTG().PushConfig(t, top)
				ate.OTG().StartProtocols(t)
				t.Log("Waiting for LACP to establish on DUT ports...")
				errs = append(errs, verifyLACPPortsState(t, dut, wantSync, p1, p2))

				return errors.Join(errs...)
			},
		},
	}
```
