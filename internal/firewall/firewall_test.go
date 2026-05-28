package firewall

import (
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// repoRoot returns the path to the limitless-audit-chain-demo repo
// root, derived from this test file's location.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// firewall_test.go is at <root>/internal/firewall/firewall_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func TestFirewall_InternalPackagesMatchExpected(t *testing.T) {
	root := repoRoot(t)
	got, err := ScanInternal(root)
	if err != nil {
		t.Fatalf("ScanInternal: %v", err)
	}
	want := ExpectedPackages()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("internal package drift:\n  got:  %v\n  want: %v", got, want)
	}
}

func TestFirewall_CmdBinariesMatchExpected(t *testing.T) {
	root := repoRoot(t)
	got, err := ScanCmd(root)
	if err != nil {
		t.Fatalf("ScanCmd: %v", err)
	}
	want := ExpectedBinaries()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cmd binary drift:\n  got:  %v\n  want: %v", got, want)
	}
}

func TestFirewall_R174CoreFivePackagesPresent(t *testing.T) {
	core := ExpectedR174CorePackages()
	if len(core) != 5 {
		t.Fatalf("R174 5-of-5 core package count: got %d, want 5", len(core))
	}
	all := ExpectedPackages()
	allSet := map[string]bool{}
	for _, p := range all {
		allSet[p] = true
	}
	for _, p := range core {
		if !allSet[p] {
			t.Fatalf("R174 core package %q absent from ExpectedPackages", p)
		}
	}
}

func TestFirewall_AllFiveR174CohortPackagesPresent(t *testing.T) {
	// R174 5-of-5 cohort maturity verification (canonical test name
	// matches bias-audit + memoria + conjure precedent).
	want := []string{"firewall", "honest", "lore", "manifest", "mirrormark"}
	got := ExpectedR174CorePackages()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("R174 5-of-5 cohort drift:\n  got:  %v\n  want: %v", got, want)
	}
}
