package manifest

import (
	"testing"
	"time"
)

func TestSeed_HasElevenEntries(t *testing.T) {
	m := Seed()
	if len(m) != 11 {
		t.Fatalf("Seed entry count: got %d, want 11", len(m))
	}
}

func TestSeed_AllReviewedByCounselFalse(t *testing.T) {
	m := Seed()
	for _, e := range m {
		if e.ReviewedByCounsel {
			t.Fatalf("entry %q: ReviewedByCounsel = true (R166 honest-default violation)", e.Key)
		}
	}
}

func TestSeed_AllFiveEmittersReferenced(t *testing.T) {
	m := Seed()
	wantKeys := []string{
		"emitter.delve.expected_surface",
		"emitter.grounded.expected_surface",
		"emitter.recall.expected_surface",
		"emitter.echo.expected_surface",
		"emitter.parallax.expected_surface",
	}
	for _, want := range wantKeys {
		found := false
		for _, e := range m {
			if e.Key == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing manifest key: %q", want)
		}
	}
}

func TestSeed_RCrossInfraEmitFirstSaturatorPresent(t *testing.T) {
	m := Seed()
	for _, e := range m {
		if e.Key == "cohort.r_cross_infra_audit_chain_emit.first_saturator" {
			return
		}
	}
	t.Fatalf("missing R-CROSS-INFRA-AUDIT-CHAIN-EMIT first-saturator key")
}

func TestEntry_IsStale_FreshAtUnknownAlwaysStale(t *testing.T) {
	e := Entry{FreshAt: FreshAtUnknown}
	if !e.IsStale(time.Now(), time.Hour) {
		t.Fatalf("FreshAtUnknown entry not stale")
	}
}

func TestEntry_IsStale_FreshEntry(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	e := Entry{FreshAt: now}
	if e.IsStale(now, 24*time.Hour) {
		t.Fatalf("same-day entry erroneously stale")
	}
}

func TestAllReviewerClasses_ThreeMembers(t *testing.T) {
	got := AllReviewerClasses()
	if len(got) != 3 {
		t.Fatalf("AllReviewerClasses len: got %d, want 3", len(got))
	}
}

func TestSortedKeys_Alphabetical(t *testing.T) {
	m := Seed()
	keys := m.SortedKeys()
	for i := 1; i < len(keys); i++ {
		if keys[i-1] > keys[i] {
			t.Fatalf("SortedKeys not sorted: %q > %q at idx %d", keys[i-1], keys[i], i)
		}
	}
}
