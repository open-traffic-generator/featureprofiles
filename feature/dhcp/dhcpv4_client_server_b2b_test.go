// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dhcp

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	otg "github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// The testbed consists of ate:port1 -> ate:port2
//
// RUN cmd:
// go test -v feature/dhcp/dhcpv4_client_server_b2b_test.go \
// -binding $HOME/featuresprofile-ci/otg-b2b/otg-otg.binding \
// -testbed $HOME/featuresprofile-ci/otg-b2b/otg-otg.testbed

const (
	vlan100         = 100
	NetworkInstance = "default"
	ServerPoolAddr  = "172.30.100.1"
	NoOfDHCPClients = 10
)

var (
	atePort1 = attrs.Attributes{
		Name:    "AtePort1",
		IPv4:    "172.30.1.1",
		MAC:     "00:01:01:01:01:01",
		IPv4Len: 31,
	}
	atePort2 = attrs.Attributes{
		Name:    "AtePort2",
		IPv4:    "172.30.1.2",
		MAC:     "00:03:01:01:01:01",
		IPv4Len: 31,
	}
)

func GenerateMacAddress(portNo uint32, deviceNo uint32) string {
	deviceNoAsCharFirstByte := deviceNo / 255
	deviceNoAsCharSecondByte := deviceNo % 255
	mac := fmt.Sprintf("00:%02x:00:%02x:%02x:00", portNo+1, deviceNoAsCharFirstByte, deviceNoAsCharSecondByte)
	return mac
}

// WaitForDhcpClients maps through all the dhcp clients to verify expected DHCP counters
func WaitForDhcpClients(t *testing.T, otg *otg.OTG, c gosnappi.Config) {
	dhcpNames := []string{}
	for _, d := range c.Devices().Items() {
		for _, e := range d.Ethernets().Items() {
			for _, dhcp := range e.Dhcpv4Interfaces().Items() {
				dhcpNames = append(dhcpNames, dhcp.Name())
			}
		}
	}

	for _, dhcpName := range dhcpNames {
		got, ok := gnmi.Watch(t, otg, gnmi.OTG().Dhcpv4Client(dhcpName).Counters().DiscoversSent().State(), time.Minute, func(val *ygnmi.Value[uint64]) bool {
			val1, present := val.Val()
			t.Logf("DHCP DiscoversSent  %v %v", gnmi.OTG().Dhcpv4Client(dhcpName).Counters().DiscoversSent().State(), val1)
			return present && val1 >= 1
		}).Await(t)
		if !ok {
			t.Fatalf("Did not receive DHCP Expected stats for client %s, last got: %v", dhcpName, got)
		}
		got1, ok1 := gnmi.Watch(t, otg, gnmi.OTG().Dhcpv4Client(dhcpName).Counters().OffersReceived().State(), time.Minute, func(val *ygnmi.Value[uint64]) bool {
			val1, present := val.Val()
			t.Logf("DHCP OffersReceived  %v %v", gnmi.OTG().Dhcpv4Client(dhcpName).Counters().OffersReceived().State(), val1)
			return present && val1 >= 1
		}).Await(t)
		if !ok1 {
			t.Fatalf("Did not receive DHCP Expected stats for client %s, last got: %v", dhcpName, got1)
		}
		got2, ok2 := gnmi.Watch(t, otg, gnmi.OTG().Dhcpv4Client(dhcpName).Counters().RequestsSent().State(), time.Minute, func(val *ygnmi.Value[uint64]) bool {
			val1, present := val.Val()
			t.Logf("DHCP RequestsSent  %v %v", gnmi.OTG().Dhcpv4Client(dhcpName).Counters().RequestsSent().State(), val1)
			return present && val1 >= 1
		}).Await(t)
		if !ok2 {
			t.Fatalf("Did not receive DHCP Expected stats for client %s, last got: %v", dhcpName, got2)
		}
		got3, ok3 := gnmi.Watch(t, otg, gnmi.OTG().Dhcpv4Client(dhcpName).Counters().AcksReceived().State(), time.Minute, func(val *ygnmi.Value[uint64]) bool {
			val1, present := val.Val()
			t.Logf("DHCP AcksReceived  %v %v", gnmi.OTG().Dhcpv4Client(dhcpName).Counters().RequestsSent().State(), val1)
			return present && val1 >= 1
		}).Await(t)
		if !ok3 {
			t.Fatalf("Did not receive DHCP Expected stats for client %s, last got: %v", dhcpName, got3)
		}
	}
}

// configureOTG configures the interfaces,DHCP protocols on an OTG.
func configureOTG(t *testing.T, otg *otg.OTG) gosnappi.Config {
	config := gosnappi.NewConfig()
	port1 := config.Ports().Add().SetName("port1")
	port2 := config.Ports().Add().SetName("port2")
	// OTG DHCP Client configuration
	for i := 1; i <= NoOfDHCPClients; i++ {
		// add device
		deviceName := fmt.Sprintf("DHCPv4Client%d", i)
		devDhcp1 := config.Devices().Add().SetName(atePort1.Name + deviceName)
		// ATE1 dhcp ethernet
		ethName := fmt.Sprintf(".Eth%d", i)
		macAddr := GenerateMacAddress(0, uint32(i))
		devDhcpEth1 := devDhcp1.Ethernets().Add().SetName(atePort1.Name + ethName).SetMac(macAddr)
		devDhcpEth1.Connection().SetPortName(port1.Name())
		// ATE1 dhcp vlan
		vlanName := fmt.Sprintf(".Vlan%d", i)
		devDhcpEthVlan1 := devDhcpEth1.Vlans().Add().SetName(atePort1.Name + vlanName)
		devDhcpEthVlan1.SetId(vlan100)
		// ATE1  DHCP Client
		dhcpName := fmt.Sprintf("DHCPv4Client%d", i)
		dhcpclient := devDhcpEth1.Dhcpv4Interfaces().Add().
			SetName(dhcpName)
		dhcpclient.FirstServer()
		dhcpclient.ParametersRequestList().
			SetSubnetMask(true).
			SetRouter(true).
			SetRenewalTimer(true)
	}

	// ATE2 DHCP Server connection
	devDhcpServer1 := config.Devices().Add().SetName(atePort2.Name + "DHCPv4Server")
	//ATE2 dhcp ethernet
	devDhcpServerEth := devDhcpServer1.Ethernets().Add().SetName(atePort2.Name + ".Eth").SetMac(atePort2.MAC)
	devDhcpServerEth.Connection().SetPortName(port2.Name())
	// // ATE2 dhcp vlan
	devDhcpServerEthVlan := devDhcpServerEth.Vlans().Add().SetName(atePort2.Name + ".Vlan")
	devDhcpServerEthVlan.SetId(vlan100)
	// ATE2 dhcp IPv4
	devDhcpServerIPv4 := devDhcpServerEth.Ipv4Addresses().Add().SetName(atePort2.Name + ".IPv4")
	devDhcpServerIPv4.SetAddress(atePort2.IPv4).SetGateway("0.0.0.0").SetPrefix(uint32(atePort2.IPv4Len))

	// ATE2 DHCP Server
	d2Dhcpv4Server := devDhcpServer1.DhcpServer().Ipv4Interfaces().Add().
		SetName("DHCPv4Server1")

	d2Dhcpv4Server.SetIpv4Name(devDhcpServerIPv4.Name()).AddressPools().
		Add().SetName("ServerPool1").
		SetLeaseTime(3600).
		SetStartAddress(ServerPoolAddr).
		SetStep(1).
		SetCount(NoOfDHCPClients).
		SetPrefixLength(16).
		Options().SetRouterAddress(devDhcpServerIPv4.Address()).SetEchoRelayWithTlv82(true)

	t.Logf("Pushing config to OTG and starting protocols...")
	otg.PushConfig(t, config)
	otg.StartProtocols(t)
	return config
}

// verifyOTGDHCPv4ClientTelemetry to verify the DHCP interface values
func verifyOTGDHCPv4ClientTelemetry(t *testing.T, otg *otg.OTG, c gosnappi.Config, dhcpAddress string) {
	for _, d := range c.Devices().Items() {
		for _, ip := range d.Ethernets().Items() {
			for _, configPeer := range ip.Dhcpv4Interfaces().Items() {
				nbrPath := gnmi.OTG().Dhcpv4Client(configPeer.Name())
				_, ok := gnmi.Watch(t, otg, nbrPath.Interface().Address().State(), time.Minute, func(val *ygnmi.Value[string]) bool {
					currAddr, ok := val.Val()
					t.Logf("DHCP %v Addr: %v ", configPeer.Name(), currAddr)
					return ok
				}).Await(t)
				if !ok {
					// fptest.LogQuery(t, "DHCP Obtained Address  %v %v", nbrPath.Interface().Address().State(), gnmi.Get(t, otg, nbrPath.Interface().Address().State()))
					t.Logf("DHCP Obtained Address  %v %v", nbrPath.Interface().Address().State(), gnmi.Get(t, otg, nbrPath.Interface().Address().State()))
					t.Errorf("DHCP Address Mismatch %s", configPeer.Name())
				}
			}
		}
	}
}

// LogDHCPv4ClientStates is displaying otg DHCP CLient states.
func LogDHCPv4ClientStates(t testing.TB, otg *otg.OTG, c gosnappi.Config) {
	t.Helper()
	var out strings.Builder
	out.WriteString("\nOTG DHCPv4 Client States\n")
	fmt.Fprintln(&out, strings.Repeat("-", 120))
	out.WriteString("\n")
	fmt.Fprintf(&out,
		"%-15s%-18s%-18s%-18s%-18s%-18s%-18s\n",
		"DHCP Client",
		"IPv4 Address",
		"Gateway Address",
		"Prefix Length",
		"Lease Time",
		"Renew Time",
		"Rebind Time")

	for _, d := range c.Devices().Items() {
		for _, e := range d.Ethernets().Items() {
			for _, dhcp := range e.Dhcpv4Interfaces().Items() {
				dhcpState := gnmi.Lookup(t, otg, gnmi.OTG().Dhcpv4Client(dhcp.Name()).Interface().State())
				v, isPresent := dhcpState.Val()
				if isPresent {
					ipv4addr := v.GetAddress()
					gatewayAddr := v.GetGatewayAddress()
					prefix := v.GetPrefixLength()
					leaseTime := v.GetLeaseTime()
					renewTime := v.GetRenewTime()
					rebindTime := v.GetRebindTime()
					out.WriteString(fmt.Sprintf(
						"%-15v%-18s%-18s%-18v%-18v%-18v%-18v\n",
						dhcp.Name(), ipv4addr, gatewayAddr, prefix, leaseTime, renewTime, rebindTime,
					))
				}
			}
		}
	}
	fmt.Fprintln(&out, strings.Repeat("-", 120))
	out.WriteString("\n\n")
	t.Log(out.String())
}

// TestDHCPv4ClientServer brings up dhcp client and Server
func TestDHCPv4ClientServer(t *testing.T) {
	// ATE Configuration.
	t.Logf("Start ATE Config")
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	var otgConfig gosnappi.Config

	t.Run("Configure OTG", func(t *testing.T) {
		otgConfig = configureOTG(t, otg)
	})

	//print OTG config in json for debug
	// conf, _ := otgConfig.Marshal().ToJson()
	// t.Logf("Printing config ---> %v", conf)

	// verify DHCP client Counter
	WaitForDhcpClients(t, otg, otgConfig)

	dhcpServer := gnmi.OTG().Dhcpv4Server("DHCPv4Server1")
	// Verify DHCP Server Counter
	gnmi.Watch(t, otg, dhcpServer.Counters().DiscoversReceived().State(), time.Minute, func(v *ygnmi.Value[uint64]) bool {
		val, present := v.Val()
		t.Logf("DHCP DiscoversReceived  %v %v", dhcpServer.Counters().DiscoversReceived().State(), val)
		return present && val == NoOfDHCPClients
	}).Await(t)
	gnmi.Watch(t, otg, dhcpServer.Counters().OffersSent().State(), time.Minute, func(v *ygnmi.Value[uint64]) bool {
		val, present := v.Val()
		t.Logf("DHCP OffersSent  %v %v", dhcpServer.Counters().OffersSent().State(), val)
		return present && val == NoOfDHCPClients
	}).Await(t)

	gnmi.Watch(t, otg, dhcpServer.Counters().RequestsReceived().State(), time.Minute, func(v *ygnmi.Value[uint64]) bool {
		val, present := v.Val()
		t.Logf("DHCP Request Receved  %v %v", dhcpServer.Counters().RequestsReceived().State(), val)
		return present && val == NoOfDHCPClients
	}).Await(t)

	gnmi.Watch(t, otg, dhcpServer.Counters().AcksSent().State(), time.Minute, func(v *ygnmi.Value[uint64]) bool {
		val, present := v.Val()
		t.Logf("DHCP Server Ack Sent  %v %v", dhcpServer.Counters().AcksSent().State(), val)
		return present && val == NoOfDHCPClients
	}).Await(t)

	t.Logf("Verify OTG DHCPv4 Client States")
	LogDHCPv4ClientStates(t, otg, otgConfig)
	verifyOTGDHCPv4ClientTelemetry(t, otg, otgConfig, ServerPoolAddr)
}
