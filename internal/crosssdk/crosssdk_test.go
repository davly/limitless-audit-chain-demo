package crosssdk

import (
	"bytes"
	"strings"
	"testing"
)

// TestCohortCanonicalKAT1Pinned guards against accidental drift of
// the cohort canonical KAT-1 hex constant. Any change to this string
// MUST be a coordinated cohort-wide bump.
func TestCohortCanonicalKAT1Pinned(t *testing.T) {
	const expected = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"
	if CohortCanonicalKAT1 != expected {
		t.Fatalf("CohortCanonicalKAT1 drifted: got %s want %s", CohortCanonicalKAT1, expected)
	}
}

// TestAllSDKChecksReturnsThreeSDKs guards the closed-set cohort
// cardinality. If a future M-slot adds echo-go / parallax-go cohort
// lore packages this test should be updated AT THE SAME TIME as the
// closed-set expansion.
func TestAllSDKChecksReturnsThreeSDKs(t *testing.T) {
	checks := AllSDKChecks()
	if got, want := len(checks), 3; got != want {
		t.Fatalf("AllSDKChecks() returned %d SDKs, want %d", got, want)
	}
	wantSDKs := []string{"recall-go", "grounded-go", "delve-go"}
	for i, c := range checks {
		if c.SDK != wantSDKs[i] {
			t.Errorf("AllSDKChecks()[%d].SDK = %q, want %q", i, c.SDK, wantSDKs[i])
		}
		if !strings.HasPrefix(c.ImportPath, "github.com/davly/") {
			t.Errorf("AllSDKChecks()[%d].ImportPath = %q, expected to start with github.com/davly/",
				i, c.ImportPath)
		}
	}
}

// TestEverySDKPassesParity is the load-bearing assertion: every
// SDK in the closed-set cohort must pin AND recompute the cohort
// canonical KAT-1 hex.
//
// This is the test that fails if any SDK drifts its KAT-1 constant
// or breaks its recomputation logic.
func TestEverySDKPassesParity(t *testing.T) {
	for _, c := range AllSDKChecks() {
		if c.PinnedHex != CohortCanonicalKAT1 {
			t.Errorf("%s pinned hex %s != cohort canonical %s",
				c.SDK, c.PinnedHex, CohortCanonicalKAT1)
		}
		if c.RecomputedHex != CohortCanonicalKAT1 {
			t.Errorf("%s recomputed hex %s != cohort canonical %s",
				c.SDK, c.RecomputedHex, CohortCanonicalKAT1)
		}
		if !c.Pass {
			t.Errorf("%s composite parity failed", c.SDK)
		}
	}
}

// TestAssertCrossSubstrateKAT1ParityReturnsNil — the parity assertion
// must succeed on a clean cohort.
func TestAssertCrossSubstrateKAT1Parity(t *testing.T) {
	if err := AssertCrossSubstrateKAT1Parity(); err != nil {
		t.Fatalf("AssertCrossSubstrateKAT1Parity: %v", err)
	}
}

// TestPrintReportContainsAllSDKs — the regulator-grade report MUST
// mention every SDK in the closed-set cohort by name.
func TestPrintReportContainsAllSDKs(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintReport(&buf); err != nil {
		t.Fatalf("PrintReport: %v", err)
	}
	out := buf.String()
	for _, sdk := range []string{"recall-go", "grounded-go", "delve-go"} {
		if !strings.Contains(out, sdk) {
			t.Errorf("PrintReport output missing SDK %q", sdk)
		}
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("PrintReport output missing PASS, got:\n%s", out)
	}
	if !strings.Contains(out, CohortCanonicalKAT1) {
		t.Errorf("PrintReport output missing cohort canonical KAT-1 hex")
	}
}

// TestPrintReportNamesCanonicalImportPaths — the report MUST name
// the canonical import paths so a regulator can verify by grep
// against the go.mod / source.
func TestPrintReportNamesCanonicalImportPaths(t *testing.T) {
	var buf bytes.Buffer
	_ = PrintReport(&buf)
	out := buf.String()
	wantPaths := []string{
		"github.com/davly/recall-go/cohort/lore",
		"github.com/davly/grounded-go/cohort/lore",
		"github.com/davly/delve-go/cohort/lore",
	}
	for _, p := range wantPaths {
		if !strings.Contains(out, p) {
			t.Errorf("PrintReport output missing import path %q", p)
		}
	}
}

// TestSDKChecksOrderIsStable — the SDK order must be deterministic
// across runs so the report output is reproducible / diffable.
func TestSDKChecksOrderIsStable(t *testing.T) {
	a := AllSDKChecks()
	b := AllSDKChecks()
	if len(a) != len(b) {
		t.Fatalf("length mismatch: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].SDK != b[i].SDK {
			t.Errorf("order mismatch at index %d: %s vs %s", i, a[i].SDK, b[i].SDK)
		}
	}
}
