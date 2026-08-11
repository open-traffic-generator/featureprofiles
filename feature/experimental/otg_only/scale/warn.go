package scale

import (
	"fmt"
	"strings"
	"testing"
)

// scaleWarnings collects every limit warning raised, for the end-of-run summary.
var scaleWarnings []string

// Warnf highlights a warning where it is raised and remembers it. Never fatal.
func Warnf(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	scaleWarnings = append(scaleWarnings, msg)
	border := strings.Repeat("*", 78)
	t.Logf("\n%s\n*** WARNING: %s\n%s", border, msg, border)
}

// LogWarnings repeats every warning raised. Deferred, so it runs even on failure.
func LogWarnings(t *testing.T) {
	t.Helper()
	if len(scaleWarnings) == 0 {
		return
	}
	border := strings.Repeat("*", 78)
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s\n*** %d WARNING(S) RAISED DURING THIS RUN\n%s\n", border, len(scaleWarnings), border)
	for i, w := range scaleWarnings {
		fmt.Fprintf(&b, "*** %2d. %s\n", i+1, w)
	}
	fmt.Fprintf(&b, "%s\n", border)
	t.Log(b.String())
}
