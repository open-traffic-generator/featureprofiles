package scale

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Rated per-port protocol-session capacity, per resource group (#ports x speed
// mode). An AresONE group is rated for this many sessions in total, split
// evenly over however many ports it is broken out into, so the figures halve as
// the port count doubles: 1x800G 36556, 2x400G 18278, 4x200G 9139, 8x100G 4570,
// 16x50G 2285.
const (
	aresOneGroupV4 = 36556
	aresOneGroupV6 = 26982

	// Novus 10G/1GE/100M cards in normal (non-aggregated) mode.
	novusNormalV4 = 36556
	novusNormalV6 = 26982

	// Novus 10G/1GE/100M cards in aggregated mode. NOVUS-NP10/1GE16DP does not
	// support aggregated mode and is excluded from this row in the matrix.
	novusAggregatedV4 = 60928
	novusAggregatedV6 = 60928

	// NOVUS10/1GE32S.
	novus32SV4 = 17843
	novus32SV6 = 15667

	// SERT 100G (100GE-QSFP28, 25G = 4*10G).
	sert100GV4 = 4461
	sert100GV6 = 3373

	// Rated concurrent-flow capacity per port. Zero means unrated, and
	// -scale_max_flows is then used as given.
	aresOneMaxFlows = 256
	// The whole NOVUS10/1GE/100M family, including NOVUS10/1GE32S.
	novus10GMaxFlows = 512
)

// Row names of the performance matrix. These are the keys of the "rows" object
// in card_limits.json.
const (
	rowAresOne         = "aresone"
	rowNovusNormal     = "novus_normal"
	rowNovusAggregated = "novus_aggregated"
	rowNovus32S        = "novus_1ge32s"
	rowSert100G        = "sert_100g"
)

// ---------------------------------------------------------------------------
// The card limits table
//
// The constants above are the built-in matrix. A card_limits.json next to the
// test, or one directory up, overrides it; -scale_limits_file names one
// explicitly. Which source is in force is logged at discovery along with every
// row the file changed, and a file that exists but cannot be parsed is fatal
// rather than ignored. Fields absent from a row keep their built-in value,
// which is why the JSON form uses pointers: an omitted "bgpv4" must not be
// mistaken for a deliberate 0, which means unrated and disables the check.
// ---------------------------------------------------------------------------

// limitsFileName is searched for next to the test, then one directory up.
const limitsFileName = "card_limits.json"

// limitRow is one row of the performance matrix.
type limitRow struct {
	BGPv4    uint32
	BGPv6    uint32
	MaxFlows uint32
}

// limitRowJSON is the on-disk form of a row. Every field is optional; see the
// note on pointers above.
type limitRowJSON struct {
	BGPv4    *uint32 `json:"bgpv4"`
	BGPv6    *uint32 `json:"bgpv6"`
	MaxFlows *uint32 `json:"max_flows"`
}

// cardRule rates a card the built-in matrix has no row for. Match is compared
// case-insensitively as a substring of the card type reported by the chassis,
// and the first matching rule wins over every built-in rule.
type cardRule struct {
	Match    string `json:"match"`
	BGPv4    uint32 `json:"bgpv4"`
	BGPv6    uint32 `json:"bgpv6"`
	MaxFlows uint32 `json:"max_flows"`
	// PerGroup marks BGPv4/BGPv6 as a whole-resource-group total to be split
	// evenly over the ports the group is broken out into, the way AresONE is
	// rated. Leave it false for a flat per-port figure.
	PerGroup bool `json:"per_group"`
	// Source is what the run log will cite as the reason for the limit.
	Source string `json:"source"`
}

// limitsTable is the matrix actually in force for a run.
type limitsTable struct {
	Rows  map[string]limitRow
	Cards []cardRule
	// Source describes where the table came from, for the run log.
	Source string
}

// limitsFileFormat is the on-disk form of limitsTable.
type limitsFileFormat struct {
	Rows  map[string]limitRowJSON `json:"rows"`
	Cards []cardRule              `json:"cards"`
}

// builtinLimits returns the compiled-in matrix.
func builtinLimits() *limitsTable {
	return &limitsTable{
		Source: "built-in table",
		Rows: map[string]limitRow{
			rowAresOne:         {BGPv4: aresOneGroupV4, BGPv6: aresOneGroupV6, MaxFlows: aresOneMaxFlows},
			rowNovusNormal:     {BGPv4: novusNormalV4, BGPv6: novusNormalV6, MaxFlows: novus10GMaxFlows},
			rowNovusAggregated: {BGPv4: novusAggregatedV4, BGPv6: novusAggregatedV6, MaxFlows: novus10GMaxFlows},
			rowNovus32S:        {BGPv4: novus32SV4, BGPv6: novus32SV6, MaxFlows: novus10GMaxFlows},
			rowSert100G:        {BGPv4: sert100GV4, BGPv6: sert100GV6},
		},
	}
}

// findLimitsFile returns the path of the limits file to use, or "" when there is
// none. An explicit -scale_limits_file is required to exist.
func findLimitsFile(t *testing.T) string {
	t.Helper()
	if p := strings.TrimSpace(*limitsFile); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("-scale_limits_file=%s: %v", p, err)
		}
		return p
	}
	// The test binary runs with its own package directory as the working
	// directory, in both `go test ./dir/` and `go test dir/file.go` form, so
	// these two relative paths are the test's folder and its parent.
	for _, c := range []string{limitsFileName, filepath.Join("..", limitsFileName)} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// loadedLimits caches the table so the file is read, and its banner logged,
// once per run however many times discovery is called.
var loadedLimits *limitsTable

// loadCardLimits returns the matrix in force, applying card_limits.json on top
// of the built-in table when one is present. It is fatal on a file that exists
// but cannot be used.
func loadCardLimits(t *testing.T) *limitsTable {
	t.Helper()
	if loadedLimits != nil {
		return loadedLimits
	}
	tbl := builtinLimits()
	loadedLimits = tbl

	path := findLimitsFile(t)
	if path == "" {
		tbl.Source = fmt.Sprintf("built-in table (no %s alongside the test or in its parent directory)", limitsFileName)
		return tbl
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read card limits file %s: %v\n"+
			"\tremove the file to fall back to the built-in table", path, err)
	}
	var f limitsFileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("cannot parse card limits file %s: %v\n"+
			"\tfix the file or remove it to fall back to the built-in table", path, err)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	tbl.Source = abs
	tbl.Cards = f.Cards

	// Merge field by field so an omitted field keeps its built-in value, and
	// record what changed for the log.
	var changes []string
	for name, in := range f.Rows {
		row, known := tbl.Rows[name]
		before := row
		if in.BGPv4 != nil {
			row.BGPv4 = *in.BGPv4
		}
		if in.BGPv6 != nil {
			row.BGPv6 = *in.BGPv6
		}
		if in.MaxFlows != nil {
			row.MaxFlows = *in.MaxFlows
		}
		tbl.Rows[name] = row
		switch {
		case !known:
			changes = append(changes, fmt.Sprintf("%s: new row %d/%d sessions, %d flows", name, row.BGPv4, row.BGPv6, row.MaxFlows))
		case row != before:
			changes = append(changes, fmt.Sprintf("%s: %d/%d sessions, %d flows (built-in: %d/%d, %d)",
				name, row.BGPv4, row.BGPv6, row.MaxFlows, before.BGPv4, before.BGPv6, before.MaxFlows))
		}
	}
	sort.Strings(changes)
	for _, c := range f.Cards {
		changes = append(changes, fmt.Sprintf("card rule %q: %d/%d sessions, %d flows", c.Match, c.BGPv4, c.BGPv6, c.MaxFlows))
	}

	if len(changes) == 0 {
		t.Logf("card limits: %s found but it changes nothing; the built-in table is in force", abs)
		return tbl
	}
	border := strings.Repeat("-", 78)
	var b strings.Builder
	fmt.Fprintf(&b, "\n\t\tCard limits overridden by %s\n%s\n", abs, border)
	for _, c := range changes {
		fmt.Fprintf(&b, "\t\t%s\n", c)
	}
	fmt.Fprintf(&b, "%s\n", border)
	t.Log(b.String())
	return tbl
}

// CardLimits is the rated capacity of a single port.
type CardLimits struct {
	BGPv4 uint32
	BGPv6 uint32
	// MaxFlows is 0 when the card has no published flow rating.
	MaxFlows uint32
	// Source names the matrix row these numbers came from, so a run log records
	// why a limit was applied.
	Source string
}

// Sessions returns the session limit for address family afi, which is 4 or 6.
func (l CardLimits) Sessions(afi int) uint32 {
	if afi == 6 {
		return l.BGPv6
	}
	return l.BGPv4
}

// limitsFor picks the performance-matrix row for a card in a given group mode,
// out of the table in force (built-in, or card_limits.json applied on top).
func limitsFor(ch *chassisTopology, card *chassisCard, g resourceGroup, tbl *limitsTable) CardLimits {
	t := strings.ToUpper(card.Type)

	// A card rule from the file wins over every built-in rule, so a card the
	// matrix has no row for can be rated without editing this test.
	for _, c := range tbl.Cards {
		if c.Match == "" || !strings.Contains(t, strings.ToUpper(c.Match)) {
			continue
		}
		src := c.Source
		if src == "" {
			src = fmt.Sprintf("%s rule %q", limitsFileName, c.Match)
		}
		if c.PerGroup {
			return splitOverGroup(c.BGPv4, c.BGPv6, c.MaxFlows, g, src)
		}
		return CardLimits{BGPv4: c.BGPv4, BGPv6: c.BGPv6, MaxFlows: c.MaxFlows, Source: src}
	}

	isAresOne := strings.HasPrefix(t, "S400GD") || strings.HasPrefix(t, "S800G") ||
		strings.Contains(strings.ToUpper(ch.Name), "ARESONE")

	switch {
	case isAresOne:
		r := tbl.Rows[rowAresOne]
		return splitOverGroup(r.BGPv4, r.BGPv6, r.MaxFlows, g,
			fmt.Sprintf("AresONE %s, %dx%s", card.Type, g.NumPorts, g.PortType))

	case strings.Contains(t, "SERT"):
		r := tbl.Rows[rowSert100G]
		return CardLimits{BGPv4: r.BGPv4, BGPv6: r.BGPv6, MaxFlows: r.MaxFlows, Source: "SERT 100G (100GE-QSFP28)"}

	case strings.Contains(t, "1GE32S"):
		r := tbl.Rows[rowNovus32S]
		return CardLimits{
			BGPv4:    r.BGPv4,
			BGPv6:    r.BGPv6,
			MaxFlows: r.MaxFlows,
			Source:   "NOVUS10/1GE32S",
		}

	case isNovus10G(t):
		// NOVUS-NP10/1GE16DP has no aggregated-mode row in the matrix.
		if g.Aggregated() && !strings.Contains(t, "NP10") {
			r := tbl.Rows[rowNovusAggregated]
			return CardLimits{
				BGPv4:    r.BGPv4,
				BGPv6:    r.BGPv6,
				MaxFlows: r.MaxFlows,
				Source:   fmt.Sprintf("NOVUS10/1GE/100M aggregated mode (%s, mode %q)", card.Type, g.Mode),
			}
		}
		r := tbl.Rows[rowNovusNormal]
		return CardLimits{
			BGPv4:    r.BGPv4,
			BGPv6:    r.BGPv6,
			MaxFlows: r.MaxFlows,
			Source:   fmt.Sprintf("NOVUS10/1GE/100M normal mode (%s, mode %q)", card.Type, g.Mode),
		}
	}

	return CardLimits{Source: fmt.Sprintf("card %q has no row in the performance matrix; no limit enforced", card.Type)}
}

// splitOverGroup rates a resource group whose published figure is a whole-group
// total, divided evenly over the ports it is broken out into.
func splitOverGroup(groupV4, groupV6, maxFlows uint32, g resourceGroup, what string) CardLimits {
	n := uint32(g.NumPorts)
	if n == 0 {
		n = 1
	}
	// Round to nearest, matching the published columns (36556/16 = 2285).
	return CardLimits{
		BGPv4:    (groupV4 + n/2) / n,
		BGPv6:    (groupV6 + n/2) / n,
		MaxFlows: maxFlows,
		Source:   fmt.Sprintf("%s: %d/%d per group split %d ways", what, groupV4, groupV6, n),
	}
}

// isNovus10G reports whether an upper-cased card type is one of the
// NOVUS10/1GE/100M family rows of the matrix.
func isNovus10G(t string) bool {
	for _, p := range []string{"NOVUS10/", "NOVUS-NP10/", "NOVUS1GE"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return strings.HasPrefix(t, "NOVUS ONE") || strings.HasPrefix(t, "NOVUSONE")
}

// CheckSessionLimit warns when the requested session count exceeds the
// discovered card's rating. afi is the address family, 4 or 6. It never fails
// and never clamps: the run proceeds at exactly the scale asked for, and the
// warning is repeated in the end-of-run summary. A nil inventory (card
// discovery disabled) checks nothing.
func CheckSessionLimit(t *testing.T, inv *Inventory, sessions uint32, afi int) {
	t.Helper()
	if inv == nil {
		return
	}
	lim := inv.MinLimits()

	switch want := lim.Sessions(afi); {
	case want == 0:
		t.Logf("card has no published BGPv%d session rating (%s); running %d sessions/port unchecked",
			afi, lim.Source, sessions)
	case sessions > want:
		Warnf(t, "-scale_sessions=%d exceeds the %d BGPv%d sessions/port this card is rated for (%s)",
			sessions, want, afi, lim.Source)
	default:
		t.Logf("requested %d BGPv%d sessions/port, within the card's rated %d (%s)",
			sessions, afi, want, lim.Source)
		// Both ports of a b2b pair often sit in one resource group, in which case
		// the group carries the sum of the two sides.
		if inv.SameResourceGroup() && 2*sessions > want {
			Warnf(t, "both ports share one resource group, so it carries %d sessions in total, above the %d rated for a single port",
				2*sessions, want)
		}
	}
}

// CheckFlowLimit warns when the requested flow count exceeds the discovered
// card's rated concurrent-flow capacity. Like CheckSessionLimit it only warns,
// and checks nothing on a nil inventory. Call it only when traffic is actually
// going to run.
func CheckFlowLimit(t *testing.T, inv *Inventory, maxFlows uint32) {
	t.Helper()
	if inv == nil {
		return
	}
	lim := inv.MinLimits()

	switch {
	case lim.MaxFlows == 0:
		t.Logf("card has no published flow rating; running with -scale_max_flows=%d unchecked", maxFlows)
	case maxFlows > lim.MaxFlows:
		Warnf(t, "-scale_max_flows=%d exceeds the %d concurrent flows this card is rated for (%s)",
			maxFlows, lim.MaxFlows, lim.Source)
	default:
		t.Logf("-scale_max_flows=%d, within the card's rated %d", maxFlows, lim.MaxFlows)
	}
}
