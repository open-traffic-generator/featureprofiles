# RT-2.14: IS-IS Drain Test

## Summary

Ensure that IS-IS metric change can drain traffic from a DUT trunk interface

## Canonical OC
```json
{}
```  

## Procedure
* Connect three ATE ports to the DUT
* Port-2 and port-3 each makes a one-member trunk port with the same ISIS metric 10 configured for the trunk interfaces (trunk-2 and trunk-3).  
* Configure a destination network-a connected to trunk-2 and trunk-3.
* Verify that IPv4 prefix advertised by ATE is correctly installed into DUTs forwarding table.
* Send 10K IPv4 traffic flows from ATE port-1 to network-a. Validate that traffic is going via trunk-2 and trunk-3 and there is no traffic loss
* Change the ISIS metric of trunk-2 to 1000 value. Verify prefix is correctly installed into DUTs forwarding table.Validate that 100% of the traffic is going out of only trunk-3 and there is no traffic loss.
* Revert back the ISIS metric on trunk-2. Verify prefix is correctly installed into DUTs forwarding table.Validate that the traffic is going via both trunk-2 and trunk-3, and there is no traffic loss.

## OpenConfig Path and RPC Coverage
```yaml
rpcs:
  gnmi:
    gNMI.Subscribe:
    gNMI.Set:
```

## Minimum DUT Platform Requirement

vRX
