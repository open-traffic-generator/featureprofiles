# Replay-1.1: Record/replay diff command trees test

## Summary

This is an example record/replay test. It is meant to reproduce a "couldn't
diff the command trees" error when applying certain gNMI config on Arista
devices.

At this time, no vendor is expected to run this test.

## OpenConfig Path and RPC Coverage

```yaml
rpcs:
  gnmi:
    gNMI.Get:
    gNMI.Set:
    gNMI.Subscribe:
  gribi:
    gRIBI.Get:
    gRIBI.Modify:
    gRIBI.Flush:
```
