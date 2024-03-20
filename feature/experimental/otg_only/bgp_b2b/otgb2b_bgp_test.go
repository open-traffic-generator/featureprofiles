package otg_b2b_bgp

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	otg "github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
)

const (
	trafficDuration   = 5 * time.Second
	tolerance         = 50
	tolerancePct      = 2
	routesCount       = 40
	txStartRange      = "100.1.1.1"
	rxStartRange      = "200.1.1.1"
	txStartRangev6    = "2001::202:14:0:1"
	rxStartRangev6    = "2002::202:14:0:1"
	totalPeersPerPort = 20
)

type trafficEndpoints struct {
	name, values []string
}

var (
	atePort1 = attrs.Attributes{
		Name:    "atePort1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.1",
		IPv6:    "2001:db8::192:0:2:1",
		IPv4Len: 16,
		IPv6Len: 64,
	}

	atePort2 = attrs.Attributes{
		Name:    "atePort2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.3.1",
		IPv6:    "2001:db8::192:0:3:1",
		IPv4Len: 16,
		IPv6Len: 64,
	}
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// func configureOTG_1to1(t *testing.T, otg *otg.OTG) gosnappi.Config {

// 	config := gosnappi.NewConfig()
// 	srcPort := config.Ports().Add().SetName("port1")
// 	dstPort := config.Ports().Add().SetName("port2")

// 	for i := 1; i <= totalPeersPerPort; i++ {
// 		mac, _ := incrementMAC(atePort1.MAC, i)
// 		srcDev := config.Devices().Add().SetName(atePort1.Name + "-" + strconv.Itoa(i))
// 		srcEth := srcDev.Ethernets().Add().SetName(atePort1.Name + ".Eth" + strconv.Itoa(i)).SetMac(mac)
// 		srcEth.Connection().SetPortName(srcPort.Name())
// 		srcIpv4 := srcEth.Ipv4Addresses().Add().SetName(atePort1.Name + ".IPv4-" + strconv.Itoa(i))
// 		devIpv4Addr := nextIP(net.ParseIP(atePort1.IPv4), uint(i)-1)
// 		gwIpv4Addr := nextIP(net.ParseIP(atePort2.IPv4), uint(i)-1)
// 		srcIpv4.SetAddress(devIpv4Addr.String()).SetGateway(gwIpv4Addr.String()).SetPrefix(uint32(atePort1.IPv4Len))

// 		txBgp := srcDev.Bgp().SetRouterId(devIpv4Addr.String())

// 		txBgpv4 := txBgp.Ipv4Interfaces().Add().SetIpv4Name(atePort1.Name + ".IPv4-" + strconv.Itoa(i))

// 		txBgpv4Peer := txBgpv4.
// 			Peers().
// 			Add().
// 			SetAsNumber(65000).
// 			SetAsType(gosnappi.BgpV4PeerAsType.IBGP).
// 			SetPeerAddress(gwIpv4Addr.String()).
// 			SetName("txBgpv4Peer-" + strconv.Itoa(i))

// 		txBgpv4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)

// 		txBgpv4PeerRrV4 := txBgpv4Peer.
// 			V4Routes().
// 			Add().
// 			SetNextHopIpv4Address(gwIpv4Addr.String()).
// 			SetName("txBgpv4PeerRrV4-" + strconv.Itoa(i)).
// 			SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
// 			SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)

// 		rrIp := nextIP(net.ParseIP(txStartRange), uint(i)-1)
// 		txBgpv4PeerRrV4.Addresses().Add().
// 			SetAddress(rrIp.String()).
// 			SetPrefix(32).
// 			SetCount(1).
// 			SetStep(1)

// 	}

// 	for i := 1; i <= totalPeersPerPort; i++ {

// 		mac, _ := incrementMAC(atePort2.MAC, i)
// 		srcDev := config.Devices().Add().SetName(atePort2.Name + "-" + strconv.Itoa(i))
// 		srcEth := srcDev.Ethernets().Add().SetName(atePort2.Name + ".Eth" + strconv.Itoa(i)).SetMac(mac)
// 		srcEth.Connection().SetPortName(dstPort.Name())
// 		srcIpv4 := srcEth.Ipv4Addresses().Add().SetName(atePort2.Name + ".IPv4-" + strconv.Itoa(i))
// 		devIpv4Addr := nextIP(net.ParseIP(atePort2.IPv4), uint(i)-1)
// 		gwIpv4Addr := nextIP(net.ParseIP(atePort1.IPv4), uint(i)-1)
// 		srcIpv4.SetAddress(devIpv4Addr.String()).SetGateway(gwIpv4Addr.String()).SetPrefix(uint32(atePort2.IPv4Len))

// 		txBgp := srcDev.Bgp().SetRouterId(devIpv4Addr.String())

// 		txBgpv4 := txBgp.Ipv4Interfaces().Add().SetIpv4Name(atePort2.Name + ".IPv4-" + strconv.Itoa(i))

// 		txBgpv4Peer := txBgpv4.
// 			Peers().
// 			Add().
// 			SetAsNumber(65000).
// 			SetAsType(gosnappi.BgpV4PeerAsType.IBGP).
// 			SetPeerAddress(gwIpv4Addr.String()).
// 			SetName("rxBgpv4Peer-" + strconv.Itoa(i))

// 		txBgpv4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)

// 		txBgpv4PeerRrV4 := txBgpv4Peer.
// 			V4Routes().
// 			Add().
// 			SetNextHopIpv4Address(gwIpv4Addr.String()).
// 			SetName("rxBgpv4PeerRrV4-" + strconv.Itoa(i)).
// 			SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
// 			SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)

// 		rrIp := nextIP(net.ParseIP(rxStartRange), uint(i)-1)
// 		txBgpv4PeerRrV4.Addresses().Add().
// 			SetAddress(rrIp.String()).
// 			SetPrefix(32).
// 			SetCount(1).
// 			SetStep(1)
// 	}
// 	// ATE Traffic Configuration.
// 	// t.Logf("TestBGP:start ate Traffic config")
// 	flowipv4 := config.Flows().Add().SetName("bgpv4RoutesFlow")
// 	flowipv4.Metrics().SetEnable(true)
// 	flowipv4.TxRx().Device().
// 		SetTxNames([]string{"txBgpv4PeerRrV4-1"}).
// 		SetRxNames([]string{"rxBgpv4PeerRrV4-1"})
// 	flowipv4.Size().SetFixed(512)
// 	e1 := flowipv4.Packet().Add().Ethernet()
// 	e1.Src().SetValue(atePort1.MAC)
// 	v4 := flowipv4.Packet().Add().Ipv4()
// 	v4.Src().SetValue(txStartRange)
// 	v4.Dst().SetValue(rxStartRange)

// 	t.Logf("Pushing config to ATE and starting protocols...")
// 	otg.PushConfig(t, config)
// 	// time.Sleep(40 * time.Second)
// 	otg.StartProtocols(t)
// 	// time.Sleep(40 * time.Second)

// 	return config
// }

func configureOTG_1tomany(t *testing.T, otg *otg.OTG) gosnappi.Config {

	var txEndpoints trafficEndpoints
	var rxEndpoints trafficEndpoints
	var txEndpointsv6 trafficEndpoints
	var rxEndpointsv6 trafficEndpoints
	config := gosnappi.NewConfig()
	srcPort := config.Ports().Add().SetName("port1")
	dstPort := config.Ports().Add().SetName("port2")

	// TX side config
	for i := 1; i <= totalPeersPerPort; i++ {
		mac, _ := incrementMAC(atePort1.MAC, i)
		srcDev := config.Devices().Add().SetName(atePort1.Name + "-" + strconv.Itoa(i))
		srcEth := srcDev.Ethernets().Add().SetName(atePort1.Name + ".Eth" + strconv.Itoa(i)).SetMac(mac)
		srcEth.Connection().SetPortName(srcPort.Name())
		srcIpv4 := srcEth.Ipv4Addresses().Add().SetName(atePort1.Name + ".IPv4-" + strconv.Itoa(i))
		devIpv4Addr := nextIP(net.ParseIP(atePort1.IPv4), uint(i)-1)
		srcIpv4.SetAddress(devIpv4Addr.String()).SetGateway(atePort2.IPv4).SetPrefix(uint32(atePort1.IPv4Len))
		srcIpv6 := srcEth.Ipv6Addresses().Add().SetName(atePort1.Name + ".IPv6-" + strconv.Itoa(i))
		devIpv6Addr := nextIPv6(net.ParseIP(atePort1.IPv6), 15, uint(i)-1)
		srcIpv6.SetAddress(devIpv6Addr.String()).SetGateway(atePort2.IPv6).SetPrefix(uint32(atePort1.IPv6Len))

		// bgpv4 config
		txBgp := srcDev.Bgp().SetRouterId(devIpv4Addr.String())
		txBgpv4 := txBgp.Ipv4Interfaces().Add().SetIpv4Name(atePort1.Name + ".IPv4-" + strconv.Itoa(i))
		txBgpv4Peer := txBgpv4.Peers().Add().SetAsNumber(65000).SetAsType(gosnappi.BgpV4PeerAsType.IBGP).
			SetPeerAddress(atePort2.IPv4).SetName("txBgpv4Peer-" + strconv.Itoa(i))
		txBgpv4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)
		txBgpv4PeerRrV4 := txBgpv4Peer.V4Routes().Add().SetNextHopIpv4Address(atePort2.IPv4).
			SetName("txBgpv4PeerRrV4-" + strconv.Itoa(i)).
			SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
			SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)
		rrIp := nextIP(net.ParseIP(txStartRange), (uint(i)-1)*256)
		txBgpv4PeerRrV4.Addresses().Add().SetAddress(rrIp.String()).SetPrefix(32).SetCount(routesCount).SetStep(1)
		txEndpoints.name = append(txEndpoints.name, "txBgpv4PeerRrV4-"+strconv.Itoa(i))
		txEndpoints.values = append(txEndpoints.values, rrIp.String())

		// bgpv6 config
		txBgpv6 := txBgp.Ipv6Interfaces().Add().SetIpv6Name(atePort1.Name + ".IPv6-" + strconv.Itoa(i))
		txBgpv6Peer := txBgpv6.Peers().Add().SetAsNumber(65000).SetAsType(gosnappi.BgpV6PeerAsType.IBGP).
			SetPeerAddress(atePort2.IPv6).SetName("txBgpv6Peer-" + strconv.Itoa(i))
		txBgpv6Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)
		txBgpv6PeerRrV6 := txBgpv6Peer.V6Routes().Add().SetNextHopIpv6Address(atePort2.IPv6).
			SetName("txBgpv4PeerRrV6-" + strconv.Itoa(i)).
			SetNextHopAddressType(gosnappi.BgpV6RouteRangeNextHopAddressType.IPV6).
			SetNextHopMode(gosnappi.BgpV6RouteRangeNextHopMode.MANUAL)
		rrIpv6 := nextIPv6(net.ParseIP(txStartRangev6), 13, uint(i)-1)
		txBgpv6PeerRrV6.Addresses().Add().SetAddress(rrIpv6.String()).SetPrefix(128).SetCount(routesCount).SetStep(1)
		txEndpointsv6.name = append(txEndpointsv6.name, "txBgpv4PeerRrV6-"+strconv.Itoa(i))
		txEndpointsv6.values = append(txEndpointsv6.values, rrIpv6.String())
	}

	// RX side config
	srcDev := config.Devices().Add().SetName(atePort2.Name)
	srcEth := srcDev.Ethernets().Add().SetName(atePort2.Name + ".Eth").SetMac(atePort2.MAC)
	srcEth.Connection().SetPortName(dstPort.Name())
	srcIpv4 := srcEth.Ipv4Addresses().Add().SetName(atePort2.Name + ".IPv4")
	srcIpv4.SetAddress(atePort2.IPv4).SetGateway(atePort1.IPv4).SetPrefix(uint32(atePort2.IPv4Len))
	srcIpv6 := srcEth.Ipv6Addresses().Add().SetName(atePort2.Name + ".IPv6")
	srcIpv6.SetAddress(atePort2.IPv6).SetGateway(atePort1.IPv6).SetPrefix(uint32(atePort2.IPv6Len))

	txBgp := srcDev.Bgp().SetRouterId(atePort2.IPv4)
	txBgpv4 := txBgp.Ipv4Interfaces().Add().SetIpv4Name(atePort2.Name + ".IPv4")
	txBgpv6 := txBgp.Ipv6Interfaces().Add().SetIpv6Name(atePort2.Name + ".IPv6")

	for i := 1; i <= totalPeersPerPort; i++ {
		gwIpv4Addr := nextIP(net.ParseIP(atePort1.IPv4), uint(i)-1)
		txBgpv4Peer := txBgpv4.Peers().Add().SetAsNumber(65000).SetAsType(gosnappi.BgpV4PeerAsType.IBGP).
			SetPeerAddress(gwIpv4Addr.String()).SetName("rxBgpv4Peer-" + strconv.Itoa(i))
		txBgpv4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)
		txBgpv4PeerRrV4 := txBgpv4Peer.V4Routes().Add().SetNextHopIpv4Address(gwIpv4Addr.String()).
			SetName("rxBgpv4PeerRrV4-" + strconv.Itoa(i)).
			SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
			SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)
		rrIp := nextIP(net.ParseIP(rxStartRange), (uint(i)-1)*256)
		txBgpv4PeerRrV4.Addresses().Add().SetAddress(rrIp.String()).SetPrefix(32).SetCount(routesCount).SetStep(1)
		rxEndpoints.name = append(rxEndpoints.name, "rxBgpv4PeerRrV4-"+strconv.Itoa(i))
		rxEndpoints.values = append(rxEndpoints.values, rrIp.String())

		gwIpv6Addr := nextIPv6(net.ParseIP(atePort1.IPv6), 15, uint(i)-1)
		txBgpv6Peer := txBgpv6.Peers().Add().SetAsNumber(65000).SetAsType(gosnappi.BgpV6PeerAsType.IBGP).
			SetPeerAddress(gwIpv6Addr.String()).SetName("rxBgpv6Peer-" + strconv.Itoa(i))
		txBgpv6Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)
		txBgpv6PeerRrV6 := txBgpv6Peer.V6Routes().Add().SetNextHopIpv6Address(gwIpv6Addr.String()).
			SetName("rxBgpv4PeerRrV6-" + strconv.Itoa(i)).
			SetNextHopAddressType(gosnappi.BgpV6RouteRangeNextHopAddressType.IPV6).
			SetNextHopMode(gosnappi.BgpV6RouteRangeNextHopMode.MANUAL)
		rrIpv6 := nextIPv6(net.ParseIP(rxStartRangev6), 13, uint(i)-1)
		txBgpv6PeerRrV6.Addresses().Add().SetAddress(rrIpv6.String()).SetPrefix(128).SetCount(routesCount).SetStep(1)
		rxEndpointsv6.name = append(rxEndpointsv6.name, "rxBgpv4PeerRrV6-"+strconv.Itoa(i))
		rxEndpointsv6.values = append(rxEndpointsv6.values, rrIpv6.String())

	}
	// ATE Traffic Configuration.
	// t.Logf("TestBGP:start ate Traffic config")

	for i := 0; i < totalPeersPerPort; i++ {
		flowipv4 := config.Flows().Add().SetName("bgpv4RoutesFlow-" + strconv.Itoa(i))
		flowipv4.Metrics().SetEnable(true)
		flowipv4.TxRx().Device().
			SetTxNames([]string{txEndpoints.name[i]}).
			SetRxNames([]string{rxEndpoints.name[i]})
		flowipv4.Size().SetFixed(100)
		e1 := flowipv4.Packet().Add().Ethernet()
		e1.Src().SetValue(atePort1.MAC)
		v4 := flowipv4.Packet().Add().Ipv4()
		v4.Src().Increment().SetStart(txEndpoints.values[i]).SetCount(routesCount)
		v4.Dst().Increment().SetStart(rxEndpoints.values[i]).SetCount(routesCount)

		flowipv6 := config.Flows().Add().SetName("bgpv6RoutesFlow-" + strconv.Itoa(i))
		flowipv6.Metrics().SetEnable(true)
		flowipv6.TxRx().Device().
			SetTxNames([]string{txEndpointsv6.name[i]}).
			SetRxNames([]string{rxEndpointsv6.name[i]})
		flowipv6.Size().SetFixed(100)
		e2 := flowipv6.Packet().Add().Ethernet()
		e2.Src().SetValue(atePort1.MAC)
		v6 := flowipv6.Packet().Add().Ipv6()
		v6.Src().Increment().SetStart(txEndpointsv6.values[i]).SetCount(routesCount)
		v6.Dst().Increment().SetStart(rxEndpointsv6.values[i]).SetCount(routesCount)
	}
	t.Logf("Pushing config to ATE and starting protocols...")
	otg.PushConfig(t, config)
	// time.Sleep(40 * time.Second)
	otg.StartProtocols(t)
	// time.Sleep(40 * time.Second)

	return config
}

// verifyTraffic confirms that every traffic flow has the expected amount of loss (0% or 100%
// depending on wantLoss, +- 2%).
func verifyTraffic(t *testing.T, ate *ondatra.ATEDevice, c gosnappi.Config, wantLoss bool) {
	otg := ate.OTG()
	otgutils.LogFlowMetrics(t, otg, c)
	for _, f := range c.Flows().Items() {
		t.Logf("Verifying flow metrics for flow %s\n", f.Name())
		recvMetric := gnmi.Get(t, otg, gnmi.OTG().Flow(f.Name()).State())
		txPackets := float32(recvMetric.GetCounters().GetOutPkts())
		rxPackets := float32(recvMetric.GetCounters().GetInPkts())
		lostPackets := txPackets - rxPackets
		lossPct := lostPackets * 100 / txPackets
		if !wantLoss {
			if lostPackets > tolerance {
				t.Logf("Packets received not matching packets sent. Sent: %v, Received: %v", txPackets, rxPackets)
			}
			if lossPct > tolerancePct && txPackets > 0 {
				t.Errorf("Traffic Loss Pct for Flow: %s\n got %v, want max %v pct failure", f.Name(), lossPct, tolerancePct)
			} else {
				t.Logf("Traffic Test Passed! for flow %s", f.Name())
			}
		} else {
			if lossPct < 100-tolerancePct && txPackets > 0 {
				t.Errorf("Traffic is expected to fail %s\n got %v, want max %v pct failure", f.Name(), lossPct, 100-tolerancePct)
			} else {
				t.Logf("Traffic Loss Test Passed! for flow %s", f.Name())
			}
		}

	}
}

func sendTraffic(t *testing.T, otg *otg.OTG) {
	t.Logf("Starting traffic")
	otg.StartTraffic(t)
	time.Sleep(trafficDuration)
	t.Logf("Stop traffic")
	otg.StopTraffic(t)
}

func verifyOTGBGPTelemetry(t *testing.T, otg *otg.OTG, c gosnappi.Config, state string) {
	for _, d := range c.Devices().Items() {
		for _, ip := range d.Bgp().Ipv4Interfaces().Items() {
			for _, configPeer := range ip.Peers().Items() {
				nbrPath := gnmi.OTG().BgpPeer(configPeer.Name())
				_, ok := gnmi.Watch(t, otg, nbrPath.SessionState().State(), time.Minute, func(val *ygnmi.Value[otgtelemetry.E_BgpPeer_SessionState]) bool {
					currState, ok := val.Val()
					return ok && currState.String() == state
				}).Await(t)
				if !ok {
					fptest.LogQuery(t, "BGP reported state", nbrPath.State(), gnmi.Get(t, otg, nbrPath.State()))
					t.Errorf("No BGP neighbor formed for peer %s", configPeer.Name())
				}
			}
		}
		for _, ip := range d.Bgp().Ipv6Interfaces().Items() {
			for _, configPeer := range ip.Peers().Items() {
				nbrPath := gnmi.OTG().BgpPeer(configPeer.Name())
				_, ok := gnmi.Watch(t, otg, nbrPath.SessionState().State(), time.Minute, func(val *ygnmi.Value[otgtelemetry.E_BgpPeer_SessionState]) bool {
					currState, ok := val.Val()
					return ok && currState.String() == state
				}).Await(t)
				if !ok {
					fptest.LogQuery(t, "BGP reported state", nbrPath.State(), gnmi.Get(t, otg, nbrPath.State()))
					t.Errorf("No BGP neighbor formed for peer %s", configPeer.Name())
				}
			}
		}

	}
}

// incrementMAC increments the MAC by i. Returns error if the mac cannot be parsed or overflows the mac address space
func incrementMAC(mac string, i int) (string, error) {
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		return "", err
	}
	convMac := binary.BigEndian.Uint64(append([]byte{0, 0}, macAddr...))
	convMac = convMac + uint64(i)
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, convMac)
	if err != nil {
		return "", err
	}
	newMac := net.HardwareAddr(buf.Bytes()[2:8])
	return newMac.String(), nil
}

func nextIPv6(ip net.IP, pos, inc uint) net.IP {
	ip = ip.To16()
	ip[pos] = ip[pos] + byte(inc)
	return ip
}

func nextIP(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

func TestOTGb2bBgp(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	// otgConfig := configureOTG_1to1(t, otg)
	otgConfig := configureOTG_1tomany(t, otg)

	// Verify the OTG BGP state.
	t.Logf("Verify OTG BGP sessions up")
	verifyOTGBGPTelemetry(t, otg, otgConfig, "ESTABLISHED")
	// Starting ATE Traffic and verify Traffic Flows and packet loss.
	sendTraffic(t, otg)
	verifyTraffic(t, ate, otgConfig, false)
}
