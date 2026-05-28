package honest

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestCanonicalAdvisories_ThreeMembers(t *testing.T) {
	got := CanonicalAdvisories()
	if len(got) != 3 {
		t.Fatalf("CanonicalAdvisories len: got %d, want 3", len(got))
	}
}

func TestCanonicalAdvisories_AllWarnSeverity(t *testing.T) {
	for _, a := range CanonicalAdvisories() {
		if a.Severity != SeverityWarn {
			t.Fatalf("advisory %s: severity %s, want Warn (demo cohort)", a.Code, a.Severity)
		}
	}
}

func TestCanonicalAdvisories_StableCodes(t *testing.T) {
	wantCodes := []string{
		"CROSS_INFRA_DEMO_NOT_PRODUCTION_RUNTIME",
		"UPSTREAM_SDK_STAND_INS_IN_USE",
		"SIGNATURE_VERIFIER_USES_MIRROR_MARK_TODAY",
	}
	got := CanonicalAdvisories()
	for i, want := range wantCodes {
		if got[i].Code != want {
			t.Fatalf("advisory[%d].Code: got %q, want %q", i, got[i].Code, want)
		}
	}
}

func TestLoudOnce_FiresOnceOnly(t *testing.T) {
	Reset()
	defer Reset()
	adv := Advisory{Code: "TEST_ONCE", Severity: SeverityWarn, Message: "msg", DocLink: "doc"}
	var buf bytes.Buffer
	LoudOnce(adv, &buf)
	LoudOnce(adv, &buf)
	LoudOnce(adv, &buf)
	count := strings.Count(buf.String(), LoudOncePrefix)
	if count != 1 {
		t.Fatalf("LoudOnce fired %d times, want 1", count)
	}
}

func TestLoudOnce_DifferentCodesFireSeparately(t *testing.T) {
	Reset()
	defer Reset()
	var buf bytes.Buffer
	LoudOnce(Advisory{Code: "A", Severity: SeverityWarn, Message: "m1", DocLink: "d"}, &buf)
	LoudOnce(Advisory{Code: "B", Severity: SeverityWarn, Message: "m2", DocLink: "d"}, &buf)
	count := strings.Count(buf.String(), LoudOncePrefix)
	if count != 2 {
		t.Fatalf("LoudOnce two codes fired %d times, want 2", count)
	}
}

func TestLoudOnce_ConcurrentSafe(t *testing.T) {
	Reset()
	defer Reset()
	adv := Advisory{Code: "TEST_CONCURRENT", Severity: SeverityWarn, Message: "msg", DocLink: "doc"}
	var buf bytes.Buffer
	var mu sync.Mutex
	var wg sync.WaitGroup
	wrapper := struct {
		mu  *sync.Mutex
		buf *bytes.Buffer
	}{&mu, &buf}
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local bytes.Buffer
			LoudOnce(adv, &local)
			wrapper.mu.Lock()
			wrapper.buf.Write(local.Bytes())
			wrapper.mu.Unlock()
		}()
	}
	wg.Wait()
	count := strings.Count(buf.String(), LoudOncePrefix)
	if count > 1 {
		t.Fatalf("LoudOnce concurrent fired %d times, want at most 1", count)
	}
}

func TestFindAdvisory_KnownCode(t *testing.T) {
	a, ok := FindAdvisory("CROSS_INFRA_DEMO_NOT_PRODUCTION_RUNTIME")
	if !ok {
		t.Fatalf("FindAdvisory: known code returned ok=false")
	}
	if a.Severity != SeverityWarn {
		t.Fatalf("known code severity: got %s, want Warn", a.Severity)
	}
}

func TestFindAdvisory_UnknownCode(t *testing.T) {
	_, ok := FindAdvisory("NOT_A_REAL_CODE")
	if ok {
		t.Fatalf("FindAdvisory: unknown code returned ok=true")
	}
}
