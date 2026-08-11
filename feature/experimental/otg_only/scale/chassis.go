package scale

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// Ixia chassis / card discovery
//
// Resolves the port names in the binding to the chassis, card and resource
// group they live on, derives the rated session and flow capacity, and reads
// the health counters. The IxOS CLI over SSH ("show topology") is the only
// source for the resource group layout, and that layout selects the row of the
// rating matrix; the IxOS REST API carries the per-port memory and PCPU status
// and the chassis perf counters. REST is best effort -- the SSH data alone
// yields the card type, the group mode and therefore the limits.
// ---------------------------------------------------------------------------

// it: "<chassis-host>;<card>;<port>".
type portRef struct {
	Chassis string
	Card    int
	Port    int
}

func (r portRef) String() string {
	return fmt.Sprintf("%s;%d;%d", r.Chassis, r.Card, r.Port)
}

// parsePortRef splits an ondatra binding port name into chassis, card and port.
func parsePortRef(name string) (portRef, error) {
	f := strings.Split(strings.TrimSpace(name), ";")
	if len(f) != 3 {
		return portRef{}, fmt.Errorf("port name %q is not in <chassis>;<card>;<port> form", name)
	}
	card, err := strconv.Atoi(strings.TrimSpace(f[1]))
	if err != nil {
		return portRef{}, fmt.Errorf("port name %q: bad card number: %v", name, err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(f[2]))
	if err != nil {
		return portRef{}, fmt.Errorf("port name %q: bad port number: %v", name, err)
	}
	return portRef{Chassis: strings.TrimSpace(f[0]), Card: card, Port: port}, nil
}

// topoPort is one port as reported by "show topology".
type topoPort struct {
	Number int
	Type   string // e.g. "400GBASE-CR8", "LAN SFP+", "10GBASE-T"
	Owner  string // "" when the port is not owned
	LinkUp bool
}

// resourceGroup is one resource group of a card. NumPorts and PortType are the
// two halves of the group's mode string: "2x400GBASE-CR8" is 2 ports of
// 400GBASE-CR8, "4xLAN" is 4 ports in LAN mode.
type resourceGroup struct {
	Number   int
	Mode     string // raw mode string, kept verbatim for logging
	NumPorts int
	PortType string
	Ports    []topoPort
}

// Aggregated reports whether the group runs in aggregated mode, where the whole
// group is presented as a single port.
func (g resourceGroup) Aggregated() bool {
	return strings.Contains(strings.ToLower(g.Mode), "aggregat") || g.NumPorts == 1
}

// chassisCard is one card of a chassis.
type chassisCard struct {
	Number int
	Type   string // e.g. "S400GD-16P-QDD", "NOVUS10/5/2.5/1/100M16DP"
	Serial string
	Groups []resourceGroup
}

// GroupForPort returns the resource group that owns the given port number.
func (c *chassisCard) GroupForPort(port int) *resourceGroup {
	for i := range c.Groups {
		for _, p := range c.Groups[i].Ports {
			if p.Number == port {
				return &c.Groups[i]
			}
		}
	}
	return nil
}

// chassisTopology is the "show topology" view of one chassis.
type chassisTopology struct {
	Host   string
	Name   string // e.g. "AresONE", "XGS2-HSL"
	Serial string
	Cards  []chassisCard
}

// CardByNumber returns the card in the given slot.
func (c *chassisTopology) CardByNumber(n int) *chassisCard {
	for i := range c.Cards {
		if c.Cards[i].Number == n {
			return &c.Cards[i]
		}
	}
	return nil
}

// portHealth is the per-port health read over the IxOS REST API.
type portHealth struct {
	Port int
	// RestID is the port's IxOS REST resource id, which is what the port
	// operation endpoints are keyed by -- not the card/port numbers.
	RestID       int
	MemoryMB     int
	PcpuStatus   string
	ManagementIP string
	LinkState    string
	SpeedMbps    int
	Type         string
	Transceiver  string
	Owner        string
}

// chassisPerf is the chassis-level CPU / memory sample from the IxOS REST perf
// counters. Per-port memory comes from portHealth.MemoryMB.
type chassisPerf struct {
	CPUPercent    float64
	MemInUseBytes uint64
	MemTotalBytes uint64
}

// MemPercent returns memory in use as a percentage of total.
func (p chassisPerf) MemPercent() float64 {
	if p.MemTotalBytes == 0 {
		return 0
	}
	return float64(p.MemInUseBytes) * 100 / float64(p.MemTotalBytes)
}

func (p chassisPerf) String() string {
	return fmt.Sprintf("cpu %.1f%%, memory %.2f/%.2f GiB (%.1f%%)",
		p.CPUPercent,
		float64(p.MemInUseBytes)/(1<<30), float64(p.MemTotalBytes)/(1<<30),
		p.MemPercent())
}

// resolvedPort ties one binding port name to the card and resource group it
// lives on and the limits that follow from them.
type resolvedPort struct {
	Ref    portRef
	Card   *chassisCard
	Group  *resourceGroup
	Limits CardLimits
	Health *portHealth // nil when REST was unavailable
}

// Inventory is the result of discovering every port the test will use.
type Inventory struct {
	Chassis []*chassisTopology
	Ports   []resolvedPort
	// RESTErrs records, per chassis host, why the REST API could not be used.
	// Discovery still succeeds in that case, with Health left nil.
	RESTErrs map[string]error
	// LimitsSource is where the rating matrix came from, quoted in the log so a
	// run always records which table produced the limits it applied.
	LimitsSource string
}

// discoverPorts reads the topology of every chassis referenced by portNames and
// resolves each port to its card, resource group and rated limits. portNames
// are ondatra binding names ("<chassis>;<card>;<port>").
func discoverPorts(user, pass string, portNames []string, timeout time.Duration, tbl *limitsTable) (*Inventory, error) {
	defer APITime.Track(APIChassisDiscover, time.Now())

	refs := make([]portRef, 0, len(portNames))
	for _, n := range portNames {
		r, err := parsePortRef(n)
		if err != nil {
			return nil, err
		}
		refs = append(refs, r)
	}

	inv := &Inventory{RESTErrs: map[string]error{}, LimitsSource: tbl.Source}
	byHost := map[string]*chassisTopology{}
	health := map[string]map[int]map[int]*portHealth{} // host -> card -> port

	for _, r := range refs {
		if _, ok := byHost[r.Chassis]; ok {
			continue
		}
		out, err := runIxOSCommand(r.Chassis, user, pass, "show topology", timeout)
		if err != nil {
			return nil, fmt.Errorf("chassis %s: show topology: %v", r.Chassis, err)
		}
		ch, err := parseTopology(out)
		if err != nil {
			return nil, fmt.Errorf("chassis %s: %v", r.Chassis, err)
		}
		ch.Host = r.Chassis
		byHost[r.Chassis] = ch
		inv.Chassis = append(inv.Chassis, ch)

		if h, err := fetchAllPortHealth(r.Chassis, user, pass, timeout); err != nil {
			inv.RESTErrs[r.Chassis] = err
		} else {
			health[r.Chassis] = h
		}
	}

	for _, r := range refs {
		ch := byHost[r.Chassis]
		rp := resolvedPort{Ref: r}
		card := ch.CardByNumber(r.Card)
		if card == nil {
			return nil, fmt.Errorf("chassis %s has no card %d", r.Chassis, r.Card)
		}
		rp.Card = card
		rp.Group = card.GroupForPort(r.Port)
		if rp.Group == nil {
			return nil, fmt.Errorf("chassis %s card %d has no port %d", r.Chassis, r.Card, r.Port)
		}
		rp.Limits = limitsFor(ch, card, *rp.Group, tbl)
		if byCard, ok := health[r.Chassis]; ok {
			if byPort, ok := byCard[r.Card]; ok {
				rp.Health = byPort[r.Port]
			}
		}
		inv.Ports = append(inv.Ports, rp)
	}
	return inv, nil
}

// MinLimits returns the tightest limit across every resolved port, which is
// what a test spanning those ports has to respect.
func (inv *Inventory) MinLimits() CardLimits {
	var out CardLimits
	for i, p := range inv.Ports {
		if i == 0 {
			out = p.Limits
			continue
		}
		if p.Limits.BGPv4 < out.BGPv4 {
			out.BGPv4 = p.Limits.BGPv4
			out.Source = p.Limits.Source
		}
		if p.Limits.BGPv6 < out.BGPv6 {
			out.BGPv6 = p.Limits.BGPv6
		}
		// A zero MaxFlows means "unrated"; a rated cap always wins over it.
		if p.Limits.MaxFlows != 0 && (out.MaxFlows == 0 || p.Limits.MaxFlows < out.MaxFlows) {
			out.MaxFlows = p.Limits.MaxFlows
		}
	}
	return out
}

// SameResourceGroup reports whether every resolved port shares one resource
// group. When they do, the ports compete for a single group's capacity rather
// than each getting the rated per-port figure.
func (inv *Inventory) SameResourceGroup() bool {
	if len(inv.Ports) < 2 {
		return false
	}
	first := inv.Ports[0]
	for _, p := range inv.Ports[1:] {
		if p.Ref.Chassis != first.Ref.Chassis || p.Ref.Card != first.Ref.Card ||
			p.Group.Number != first.Group.Number {
			return false
		}
	}
	return true
}

// String renders the discovered inventory as a log block.
func (inv *Inventory) String() string {
	border := strings.Repeat("-", 78)
	var b strings.Builder
	fmt.Fprintf(&b, "\n\t\tIxia chassis / card inventory\n%s\n", border)
	fmt.Fprintf(&b, "\t\trating matrix   : %s\n", inv.LimitsSource)
	for _, ch := range inv.Chassis {
		fmt.Fprintf(&b, "\t\tchassis %s: %s (SN %s)\n", ch.Host, ch.Name, ch.Serial)
		if err := inv.RESTErrs[ch.Host]; err != nil {
			fmt.Fprintf(&b, "\t\t  REST API unavailable (%v); port memory / PCPU status not read\n", err)
		}
	}
	for _, p := range inv.Ports {
		fmt.Fprintf(&b, "%s\n", border)
		fmt.Fprintf(&b, "\t\tport %s\n", p.Ref)
		fmt.Fprintf(&b, "\t\t  card %d          : %s (SN %s)\n", p.Card.Number, p.Card.Type, p.Card.Serial)
		fmt.Fprintf(&b, "\t\t  resource group  : RG%02d, mode %q (%d ports of %s)\n",
			p.Group.Number, p.Group.Mode, p.Group.NumPorts, p.Group.PortType)
		fmt.Fprintf(&b, "\t\t  rated BGPv4/v6  : %d / %d sessions per port  [%s]\n",
			p.Limits.BGPv4, p.Limits.BGPv6, p.Limits.Source)
		if p.Limits.MaxFlows > 0 {
			fmt.Fprintf(&b, "\t\t  rated max flows : %d\n", p.Limits.MaxFlows)
		} else {
			fmt.Fprintf(&b, "\t\t  rated max flows : not rated for this card\n")
		}
		if h := p.Health; h != nil {
			fmt.Fprintf(&b, "\t\t  port memory     : %d MB\n", h.MemoryMB)
			fmt.Fprintf(&b, "\t\t  port CPU (PCPU) : %s (mgmt %s)\n", h.PcpuStatus, h.ManagementIP)
			fmt.Fprintf(&b, "\t\t  link/speed/type : %s / %d Mbps / %s\n", h.LinkState, h.SpeedMbps, h.Type)
			fmt.Fprintf(&b, "\t\t  transceiver     : %s\n", h.Transceiver)
			fmt.Fprintf(&b, "\t\t  owner           : %s\n", h.Owner)
		}
	}
	if inv.SameResourceGroup() {
		fmt.Fprintf(&b, "%s\n", border)
		fmt.Fprintf(&b, "\t\tNOTE: all ports under test share one resource group; the rated\n")
		fmt.Fprintf(&b, "\t\tfigure above is per port, so the group carries their sum.\n")
	}
	fmt.Fprintf(&b, "%s\n", border)
	return b.String()
}

var (
	// "XGS2-HSL - Primary (ChassisSN XGS2-G0960034, ControllerSN 606488)"
	// "AresONE - Primary (ChassisSN MY26131006)"
	reChassis = regexp.MustCompile(`^\s*(\S+)\s+-\s+\S+\s+\(ChassisSN\s+([^,)]+)`)
	// "    +- Card 1 S400GD-16P-QDD (SN MY26131006)"
	reCard = regexp.MustCompile("^\\s*[+`|-]+-\\s*Card\\s+(\\d+)\\s+(\\S+)(?:\\s+\\(SN\\s+([^)]*)\\))?")
	// "|      +- Resource Group 01 (RG01)- 2x400GBASE-CR8 mode"
	reGroup = regexp.MustCompile(`Resource Group\s+(\d+)\s*\(RG\d+\)\s*-\s*(.+?)\s+mode\s*$`)
	// "|      +- Port 9 400GBASE-CR8 (8b0f3376498d/root/1) Link Up"
	// "|      |- Port 11 10GBASE-T Link Up"
	rePort = regexp.MustCompile(`Port\s+(\d+)\s+(.+?)(?:\s+\(([^)]*)\))?\s+Link\s+(Up|Down)\s*$`)
	// "2x400GBASE-CR8", "4xLAN"
	reMode = regexp.MustCompile(`^(\d+)x(.+)$`)
)

// parseTopology parses the output of the IxOS CLI "show topology" command.
func parseTopology(out string) (*chassisTopology, error) {
	ch := &chassisTopology{}
	var card *chassisCard
	var group *resourceGroup

	// flushGroup/flushCard attach whatever is being accumulated to its parent.
	flushGroup := func() {
		if group != nil && card != nil {
			card.Groups = append(card.Groups, *group)
		}
		group = nil
	}
	flushCard := func() {
		flushGroup()
		if card != nil {
			ch.Cards = append(ch.Cards, *card)
		}
		card = nil
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r \t")
		if line == "" {
			continue
		}
		switch {
		case ch.Name == "" && reChassis.MatchString(line):
			m := reChassis.FindStringSubmatch(line)
			ch.Name, ch.Serial = m[1], strings.TrimSpace(m[2])

		case reCard.MatchString(line):
			flushCard()
			m := reCard.FindStringSubmatch(line)
			n, _ := strconv.Atoi(m[1])
			card = &chassisCard{Number: n, Type: m[2], Serial: strings.TrimSpace(m[3])}

		case reGroup.MatchString(line):
			flushGroup()
			m := reGroup.FindStringSubmatch(line)
			n, _ := strconv.Atoi(m[1])
			group = &resourceGroup{Number: n, Mode: m[2]}
			if mm := reMode.FindStringSubmatch(group.Mode); mm != nil {
				group.NumPorts, _ = strconv.Atoi(mm[1])
				group.PortType = mm[2]
			}

		case rePort.MatchString(line):
			if group == nil {
				continue
			}
			m := rePort.FindStringSubmatch(line)
			n, _ := strconv.Atoi(m[1])
			group.Ports = append(group.Ports, topoPort{
				Number: n,
				Type:   strings.TrimSpace(m[2]),
				Owner:  strings.TrimSpace(m[3]),
				LinkUp: m[4] == "Up",
			})
		}
	}
	flushCard()

	if len(ch.Cards) == 0 {
		return nil, fmt.Errorf("no cards found in \"show topology\" output:\n%s", out)
	}
	return ch, nil
}

// runIxOSCommand runs one command in the restricted IxOS CLI over SSH and
// returns its stdout.
func runIxOSCommand(host, user, pass, cmd string, timeout time.Duration) (string, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // lab chassis, as elsewhere in this suite
		Timeout:         timeout,
	}
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %v", addr, err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("%q: %v (output: %s)", cmd, err, string(out))
	}
	return string(out), nil
}

// ixosREST is a thin IxOS REST client, authenticated with a platform session
// API key.
type ixosREST struct {
	host   string
	APIKey string
	client *http.Client
}

func newIxosREST(host, user, pass string, timeout time.Duration) (*ixosREST, error) {
	c := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Chassis serve a self-signed certificate.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, err := c.Post("https://"+host+"/platform/api/v1/auth/session",
		"application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("auth: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var out struct {
		APIKey            string `json:"APIKey"`
		Error             string `json:"error"`
		ResetWeakPassword bool   `json:"resetWeakPassword"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("auth: bad response %q", string(raw))
	}
	if out.APIKey == "" {
		msg := out.Error
		if msg == "" {
			msg = string(raw)
		}
		if out.ResetWeakPassword {
			msg += " (chassis requires the default password to be changed before it will issue an API session)"
		}
		return nil, fmt.Errorf("auth: %s", msg)
	}
	return &ixosREST{host: host, APIKey: out.APIKey, client: c}, nil
}

func (r *ixosREST) get(path string, into any) error {
	req, err := http.NewRequest(http.MethodGet, "https://"+r.host+"/chassis/api/v2/"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", r.APIKey)
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(raw)))
	}
	return json.Unmarshal(raw, into)
}

// fetchAllPortHealth reads every port on the chassis, keyed by card then port.
func fetchAllPortHealth(host, user, pass string, timeout time.Duration) (map[int]map[int]*portHealth, error) {
	r, err := newIxosREST(host, user, pass, timeout)
	if err != nil {
		return nil, err
	}
	var ports []struct {
		ID               int    `json:"id"`
		CardNumber       int    `json:"cardNumber"`
		PortNumber       int    `json:"portNumber"`
		PortMemory       int    `json:"portMemory"`
		PcpuStatus       string `json:"pcpuStatus"`
		ManagementIP     string `json:"managementIp"`
		LinkState        string `json:"linkState"`
		Speed            int    `json:"speed"`
		Type             string `json:"type"`
		TransceiverModel string `json:"transceiverModel"`
		Owner            string `json:"owner"`
	}
	if err := r.get("ixos/ports", &ports); err != nil {
		return nil, err
	}
	out := map[int]map[int]*portHealth{}
	for _, p := range ports {
		if out[p.CardNumber] == nil {
			out[p.CardNumber] = map[int]*portHealth{}
		}
		out[p.CardNumber][p.PortNumber] = &portHealth{
			Port:         p.PortNumber,
			RestID:       p.ID,
			MemoryMB:     p.PortMemory,
			PcpuStatus:   p.PcpuStatus,
			ManagementIP: p.ManagementIP,
			LinkState:    p.LinkState,
			SpeedMbps:    p.Speed,
			Type:         p.Type,
			Transceiver:  p.TransceiverModel,
			Owner:        p.Owner,
		}
	}
	return out, nil
}

// fetchChassisPerf returns the most recent chassis CPU / memory sample. IxOS
// keeps a rolling window of samples; the last one is the freshest.
func fetchChassisPerf(host, user, pass string, timeout time.Duration) (*chassisPerf, error) {
	defer APITime.Track(APIChassisPerf, time.Now())

	r, err := newIxosREST(host, user, pass, timeout)
	if err != nil {
		return nil, err
	}
	var samples []struct {
		Sequence      uint64  `json:"sequence"`
		MemInUseBytes uint64  `json:"memoryInUseBytes"`
		MemTotalBytes uint64  `json:"memoryTotalBytes"`
		CPUPercent    float64 `json:"cpuUsagePercent"`
	}
	if err := r.get("ixos/perfcounters", &samples); err != nil {
		return nil, err
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("no perf counter samples returned")
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].Sequence < samples[j].Sequence })
	last := samples[len(samples)-1]
	return &chassisPerf{
		CPUPercent:    last.CPUPercent,
		MemInUseBytes: last.MemInUseBytes,
		MemTotalBytes: last.MemTotalBytes,
	}, nil
}

// fetchPortHealthFor re-reads the per-port memory / PCPU status for the given
// ports, so a caller can sample it again after a run.
func fetchPortHealthFor(user, pass string, refs []portRef, timeout time.Duration) (map[string]*portHealth, error) {
	defer APITime.Track(APIChassisPortInfo, time.Now())

	byHost := map[string]map[int]map[int]*portHealth{}
	out := map[string]*portHealth{}
	for _, r := range refs {
		if _, ok := byHost[r.Chassis]; !ok {
			h, err := fetchAllPortHealth(r.Chassis, user, pass, timeout)
			if err != nil {
				return nil, err
			}
			byHost[r.Chassis] = h
		}
		if byCard, ok := byHost[r.Chassis][r.Card]; ok {
			if p, ok := byCard[r.Port]; ok {
				out[r.String()] = p
			}
		}
	}
	return out, nil
}

// DiscoverChassis resolves the bound ATE ports to the Ixia chassis, card and
// resource group they live on. Returns nil when -scale_chassis_check=false.
func DiscoverChassis(t *testing.T, ate *ondatra.ATEDevice) *Inventory {
	t.Helper()
	if !*chassisCheck {
		t.Log("card discovery disabled (-scale_chassis_check=false); no card limits enforced")
		return nil
	}
	var names []string
	for _, id := range []string{"port1", "port2"} {
		names = append(names, ate.Port(t, id).Name())
	}
	tbl := loadCardLimits(t)
	inv, err := discoverPorts(*chassisUser, *chassisPass, names, *chassisTimeout, tbl)
	if err != nil {
		t.Fatalf("cannot discover the Ixia card behind ports %v: %v\n"+
			"\tset -scale_chassis_user/-scale_chassis_pass, or pass -scale_chassis_check=false to run without card limit enforcement",
			names, err)
	}
	t.Log(inv.String())
	return inv
}

// LogCardHealth samples per-port memory and PCPU status plus chassis CPU and
// memory. Diagnostic only: failures are logged, never fatal.
func LogCardHealth(t *testing.T, inv *Inventory, when string) {
	t.Helper()
	if inv == nil {
		return
	}
	refs := make([]portRef, 0, len(inv.Ports))
	seen := map[string]bool{}
	for _, p := range inv.Ports {
		refs = append(refs, p.Ref)
		if seen[p.Ref.Chassis] {
			continue
		}
		seen[p.Ref.Chassis] = true
		perf, err := fetchChassisPerf(p.Ref.Chassis, *chassisUser, *chassisPass, *chassisTimeout)
		if err != nil {
			t.Logf("[%s] chassis %s CPU/memory unavailable: %v", when, p.Ref.Chassis, err)
			continue
		}
		t.Logf("[%s] chassis %s: %s", when, p.Ref.Chassis, perf)
	}

	health, err := fetchPortHealthFor(*chassisUser, *chassisPass, refs, *chassisTimeout)
	if err != nil {
		t.Logf("[%s] port memory / PCPU status unavailable: %v", when, err)
		return
	}
	for _, r := range refs {
		h, ok := health[r.String()]
		if !ok {
			t.Logf("[%s] port %s: no health reported", when, r)
			continue
		}
		t.Logf("[%s] port %s: memory %d MB, PCPU %s, link %s, speed %d Mbps, owner %q",
			when, r, h.MemoryMB, h.PcpuStatus, h.LinkState, h.SpeedMbps, h.Owner)
	}
}
