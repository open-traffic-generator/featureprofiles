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

package otgutils

import (
	"fmt"

	"github.com/open-traffic-generator/snappi/gosnappi"
)

/*
This utility will generate ISIS ST OTG Topology
*/

// no_ipv4_routes, start_ipv4_prefix. ipv4_route_prefix_length, ipv4_prefix_increment

type v4IsisStRouteInfo struct {
	addressFirstOctet string
	prefix            int
	count             int
}

func (obj *v4IsisStRouteInfo) SetAddressFirstOctet(addressFirstOctet string) *v4IsisStRouteInfo {
	obj.addressFirstOctet = addressFirstOctet
	return obj
}

func (obj *v4IsisStRouteInfo) SetPrefix(prefix int) *v4IsisStRouteInfo {
	obj.prefix = prefix
	return obj
}

func (obj *v4IsisStRouteInfo) SetCount(count int) *v4IsisStRouteInfo {
	obj.count = count
	return obj
}

type v6IsisStRouteInfo struct {
	addressFirstOctet string
	prefix            int
	count             int
}

func (obj *v6IsisStRouteInfo) SetAddressFirstOctet(addressFirstOctet string) *v6IsisStRouteInfo {
	obj.addressFirstOctet = addressFirstOctet
	return obj
}

func (obj *v6IsisStRouteInfo) SetPrefix(prefix int) *v6IsisStRouteInfo {
	obj.prefix = prefix
	return obj
}

func (obj *v6IsisStRouteInfo) SetCount(count int) *v6IsisStRouteInfo {
	obj.count = count
	return obj
}

type gridIsisSt struct {
	config             gosnappi.Config
	row                int
	col                int
	systemIdFirstOctet string
	linkIp4FirstOctet  string
	linkIp6FirstOctet  string
	v4StRoute          *v4IsisStRouteInfo
	v6StRoute          *v6IsisStRouteInfo
}

func (obj *gridIsisSt) SetRow(row int) *gridIsisSt {
	obj.row = row
	return obj
}

func (obj *gridIsisSt) SetCol(col int) *gridIsisSt {
	obj.col = col
	return obj
}

func (obj *gridIsisSt) SetSystemIdFirstOctet(firstOctSysId string) *gridIsisSt {
	obj.systemIdFirstOctet = firstOctSysId
	return obj
}

func (obj *gridIsisSt) SetLinkIp4FirstOctet(oct string) *gridIsisSt {
	obj.linkIp4FirstOctet = oct
	return obj
}

func (obj *gridIsisSt) SetLinkIp6FirstOctet(oct string) *gridIsisSt {
	obj.linkIp6FirstOctet = oct
	return obj
}

func (obj *gridIsisSt) V4RouteInfo() *v4IsisStRouteInfo {
	obj.v4StRoute = &v4IsisStRouteInfo{
		addressFirstOctet: "10",
		prefix:            32,
		count:             1,
	}
	return obj.v4StRoute
}

func (obj *gridIsisSt) V6RouteInfo() *v6IsisStRouteInfo {
	obj.v6StRoute = &v6IsisStRouteInfo{
		addressFirstOctet: "10",
		prefix:            64,
		count:             1,
	}
	return obj.v6StRoute
}

func (obj *gridIsisSt) GenerateTopology() gridIsisStTopo {
	if obj.row <= 1 || obj.col <= 1 {
		fmt.Errorf("ST Grid must have more than One row or col.")
	}

	if len(obj.systemIdFirstOctet) == 0 {
		fmt.Errorf("systemIdFirstOctet must be configured.")
	}

	gridTopo := gridIsisStTopo{
		linkIp4FirstOctet: obj.linkIp4FirstOctet,
		linkIp6FirstOctet: obj.linkIp6FirstOctet,
	}
	gridTopo.gridNodes = make([][]int, obj.row)
	for i := range gridTopo.gridNodes {
		gridTopo.gridNodes[i] = make([]int, obj.col)
	}

	nodeIdx := 0
	for rowIdx := 0; rowIdx < obj.row; rowIdx++ {
		for colIdx := 0; colIdx < obj.col; colIdx++ {
			gridTopo.gridNodes[rowIdx][colIdx] = nodeIdx
			dev := createSimDev(obj.config, nodeIdx, obj.systemIdFirstOctet,
				rowIdx, colIdx, obj.v4StRoute, obj.v6StRoute)
			gridTopo.devices = append(gridTopo.devices, dev)

			nodeIdx += 1
		}
	}

	for rowIdx, row1 := range gridTopo.gridNodes {
		for colIdx, val1 := range row1 {
			if colIdx+1 != obj.col {
				val2 := row1[colIdx+1]
				madeLink(gridTopo.devices[val1], gridTopo.devices[val2],
					val1, val2, obj.linkIp4FirstOctet, obj.linkIp6FirstOctet)
			}
			if rowIdx+1 != obj.row {
				row2 := gridTopo.gridNodes[rowIdx+1]
				val2 := row2[colIdx]
				madeLink(gridTopo.devices[val1], gridTopo.devices[val2],
					val1, val2, obj.linkIp4FirstOctet, obj.linkIp6FirstOctet)
			}
		}
	}

	return gridTopo
}

func NewGridisisSt(c gosnappi.Config) gridIsisSt {
	gridSt := gridIsisSt{
		config:    c,
		v4StRoute: nil,
		v6StRoute: nil,
	}
	return gridSt
}

type gridIsisStTopo struct {
	gridNodes         [][]int
	devices           []gosnappi.Device
	linkIp4FirstOctet string
	linkIp6FirstOctet string
}

func (obj *gridIsisStTopo) Connect(emuDev gosnappi.Device, rowIdx int, colIdx int) {
	devIdx := obj.gridNodes[rowIdx][colIdx]
	simDev := obj.devices[devIdx]
	emuIdx := len(obj.devices)
	madeLink(emuDev, simDev, emuIdx, devIdx,
		obj.linkIp4FirstOctet, obj.linkIp6FirstOctet)
}

func (obj *gridIsisStTopo) GetDevice(rowIdx int, colIdx int) gosnappi.Device {
	devIdx := obj.gridNodes[rowIdx][colIdx]
	simDev := obj.devices[devIdx]
	return simDev
}

func createSimDev(config gosnappi.Config, nodeIdx int, systemIdFirstOctet string, srcIdx int, dstIdx int, v4RouteInfo *v4IsisStRouteInfo, v6RouteInfo *v6IsisStRouteInfo) gosnappi.Device {
	otgIdx := nodeIdx + 1

	var deviceName string
	var teRtrId string

	if dstIdx == -1 {
		deviceName = fmt.Sprintf("T%sd%d.sim.%d", systemIdFirstOctet, otgIdx, srcIdx)
		teRtrId = fmt.Sprintf("10.10.0.%d", srcIdx)

	} else {
		deviceName = fmt.Sprintf("T%sd%d.sim.%d.%d", systemIdFirstOctet, otgIdx, srcIdx, dstIdx)
		teRtrId = fmt.Sprintf("10.10.%d.%d", srcIdx, dstIdx)
	}
	dev := config.Devices().Add().SetName(deviceName)
	systemId := fmt.Sprintf("%s00000000%02x", systemIdFirstOctet, otgIdx)
	simRtrIsis := dev.Isis().
		SetName(deviceName + ".isis").
		SetSystemId(systemId)

	simRtrIsis.Basic().SetIpv4TeRouterId(teRtrId).
		SetHostname(deviceName).
		SetEnableWideMetric(true)

	if v4RouteInfo != nil {
		v4Route := simRtrIsis.V4Routes().Add().
			SetName(simRtrIsis.Name() + ".isis.v4routes").
			SetLinkMetric(10).
			SetOriginType(gosnappi.IsisV4RouteRangeOriginType.INTERNAL)

		ipv4Prefix := fmt.Sprintf("%s.0.%d.0", v4RouteInfo.addressFirstOctet, srcIdx+1)
		if dstIdx != -1 {
			ipv4Prefix = fmt.Sprintf("%s.%d.%d.0", v4RouteInfo.addressFirstOctet, srcIdx+1, dstIdx+1)
		}
		v4Route.Addresses().Add().
			SetAddress(ipv4Prefix).
			SetPrefix(uint32(v4RouteInfo.prefix)).
			SetCount(uint32(v4RouteInfo.count))
	}

	if v6RouteInfo != nil {
		v6Route := simRtrIsis.V6Routes().Add().
			SetName(simRtrIsis.Name() + ".isis.v6routes").
			SetLinkMetric(10).
			SetOriginType(gosnappi.IsisV6RouteRangeOriginType.INTERNAL)

		ipv6Prefix := fmt.Sprintf("%s::%d:0", v6RouteInfo.addressFirstOctet, srcIdx+1)
		if dstIdx != -1 {
			ipv6Prefix = fmt.Sprintf("%s::%d:%d:0", v6RouteInfo.addressFirstOctet, srcIdx+1, dstIdx+1)
		}

		v6Route.Addresses().Add().
			SetAddress(ipv6Prefix).
			SetPrefix(uint32(v6RouteInfo.prefix)).
			SetCount(uint32(v6RouteInfo.count))
	}

	return dev
}

func madeLink(d1 gosnappi.Device, d2 gosnappi.Device, _idx1 int, _idx2 int, linkIp4FirstOctet string, linkIp6FirstOctet string) {
	// fmt.Println(_idx1, _idx2)
	d1name := d1.Name()
	d2name := d2.Name()
	// log.Printf("Connecting %s to %s \n", d1name, d2name)

	idx1 := _idx1 + 1
	idx2 := _idx2 + 1

	eth1Name := fmt.Sprintf("%veth%d", d1name, len(d1.Ethernets().Items())+1)
	eth2Name := fmt.Sprintf("%veth%d", d2name, len(d2.Ethernets().Items())+1)
	macAdd1 := fmt.Sprintf("00:00:dd:ee:0%d:0%d", idx1, idx2)
	macAdd2 := fmt.Sprintf("00:00:dd:ee:0%d:0%d", idx2, idx1)
	isisInf1Name := fmt.Sprintf("%vIsisinf%d", d1name, len(d1.Isis().Interfaces().Items())+1)
	isisInf2Name := fmt.Sprintf("%vIsisinf%d", d2name, len(d2.Isis().Interfaces().Items())+1)

	d1eth := d1.Ethernets().Add().
		SetName(eth1Name).
		SetMac(macAdd1)
	d1eth.Connection().SimulatedLink().SetRemoteSimulatedLink(eth2Name)

	isis1Inf := d1.Isis().Interfaces().Add().
		SetName(isisInf1Name).
		SetEthName(eth1Name)
	isis1Inf.TrafficEngineering().Add().PriorityBandwidths()

	d2eth := d2.Ethernets().Add().
		SetName(eth2Name).
		SetMac(macAdd2)
	d2eth.Connection().SimulatedLink().SetRemoteSimulatedLink(eth1Name)

	isis2Inf := d2.Isis().Interfaces().Add().
		SetName(isisInf2Name).
		SetEthName(eth2Name)
	isis2Inf.TrafficEngineering().Add().PriorityBandwidths()

	if len(linkIp4FirstOctet) == 0 && len(linkIp6FirstOctet) == 0 {
		fmt.Errorf("linkIp4FirstOctet or linkIp6FirstOctet must be configure.")
	}

	if len(linkIp4FirstOctet) != 0 {
		ip1Name := fmt.Sprintf("%vip4", eth1Name)
		ip2Name := fmt.Sprintf("%vip4", eth2Name)
		ip1 := fmt.Sprintf("%s.%d.%d.1", linkIp4FirstOctet, idx1, idx2)
		ip2 := fmt.Sprintf("%s.%d.%d.2", linkIp4FirstOctet, idx1, idx2)

		d1eth.Ipv4Addresses().Add().
			SetName(ip1Name).
			SetAddress(ip1).
			SetGateway(ip2)

		d2eth.Ipv4Addresses().Add().
			SetName(ip2Name).
			SetAddress(ip2).
			SetGateway(ip1)
	}

	if len(linkIp6FirstOctet) != 0 {
		ip1Name := fmt.Sprintf("%vip6", eth1Name)
		ip2Name := fmt.Sprintf("%vip6", eth2Name)
		ip1 := fmt.Sprintf("%s::%d:%d:1", linkIp6FirstOctet, idx1, idx2)
		ip2 := fmt.Sprintf("%s::%d:%d:2", linkIp6FirstOctet, idx1, idx2)

		d1eth.Ipv6Addresses().Add().
			SetName(ip1Name).
			SetAddress(ip1).
			SetGateway(ip2)

		d2eth.Ipv6Addresses().Add().
			SetName(ip2Name).
			SetAddress(ip2).
			SetGateway(ip1)
	}

}

type ringIsisSt struct {
	config             gosnappi.Config
	noOfNodes          int
	systemIdFirstOctet string
	linkIp4FirstOctet  string
	linkIp6FirstOctet  string
	v4StRoute          *v4IsisStRouteInfo
	v6StRoute          *v6IsisStRouteInfo
}

func (obj *ringIsisSt) SetNoOfNodes(noOfNodes int) *ringIsisSt {
	obj.noOfNodes = noOfNodes
	return obj
}

func (obj *ringIsisSt) SetSystemIdFirstOctet(firstOctSysId string) *ringIsisSt {
	obj.systemIdFirstOctet = firstOctSysId
	return obj
}

func (obj *ringIsisSt) SetLinkIp4FirstOctet(oct string) *ringIsisSt {
	obj.linkIp4FirstOctet = oct
	return obj
}

func (obj *ringIsisSt) SetLinkIp6FirstOctet(oct string) *ringIsisSt {
	obj.linkIp6FirstOctet = oct
	return obj
}

func (obj *ringIsisSt) V4RouteInfo() *v4IsisStRouteInfo {
	obj.v4StRoute = &v4IsisStRouteInfo{
		addressFirstOctet: "10",
		prefix:            32,
		count:             1,
	}
	return obj.v4StRoute
}

func (obj *ringIsisSt) V6RouteInfo() *v6IsisStRouteInfo {
	obj.v6StRoute = &v6IsisStRouteInfo{
		addressFirstOctet: "10",
		prefix:            64,
		count:             1,
	}
	return obj.v6StRoute
}

func (obj *ringIsisSt) GenerateTopology() ringIsisStTopo {
	ringTopo := ringIsisStTopo{
		linkIp4FirstOctet: obj.linkIp4FirstOctet,
		linkIp6FirstOctet: obj.linkIp6FirstOctet,
	}

	for nodeIdx := 0; nodeIdx < obj.noOfNodes; nodeIdx++ {
		dstIdx := -1
		dev := createSimDev(obj.config, nodeIdx, obj.systemIdFirstOctet,
			nodeIdx, dstIdx, obj.v4StRoute, obj.v6StRoute)
		ringTopo.devices = append(ringTopo.devices, dev)
	}

	for currentIdx, currentDev := range ringTopo.devices {
		nextIdx := 0
		if currentIdx+1 != len(ringTopo.devices) {
			nextIdx = currentIdx + 1
		}
		nextDev := ringTopo.devices[nextIdx]
		madeLink(currentDev, nextDev,
			currentIdx, nextIdx, obj.linkIp4FirstOctet, obj.linkIp6FirstOctet)
	}

	return ringTopo
}

func NewRingIsisSt(c gosnappi.Config) ringIsisSt {
	gridSt := ringIsisSt{
		config:    c,
		v4StRoute: nil,
		v6StRoute: nil,
	}
	return gridSt
}

type ringIsisStTopo struct {
	devices           []gosnappi.Device
	linkIp4FirstOctet string
	linkIp6FirstOctet string
}

func (obj *ringIsisStTopo) Connect(emuDev gosnappi.Device, nodeIdx int) {
	simDev := obj.devices[nodeIdx]
	emuIdx := len(obj.devices)
	madeLink(emuDev, simDev, emuIdx, nodeIdx,
		obj.linkIp4FirstOctet, obj.linkIp6FirstOctet)
}

func (obj *ringIsisStTopo) GetDevice(nodeIdx int) gosnappi.Device {
	simDev := obj.devices[nodeIdx]
	return simDev
}
