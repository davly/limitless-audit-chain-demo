// Package firewall implements the R145.C FIREWALL-TEST-DISCIPLINE
// pin for limitless-audit-chain-demo — structural firewall against
// internal/ + cmd/ drift.
package firewall

import (
	"os"
	"path/filepath"
	"sort"
)

// ExpectedPackages returns the canonical list of internal/ packages
// limitless-audit-chain-demo ships as of W58 (2026-05-29 R193 wire-in)
// + the quarry-db x-poll persist addition.
//
// 10 packages (8 inception + crosssdk W58 wire-in + persist x-poll):
//   - chain      (load-bearing composition library — the SHOWCASE)
//   - crosssdk   (W58 R193 real-import wire-in — recall+grounded+delve cohort/lore)
//   - emitters   (I20 stand-ins for delve/grounded/recall/echo/parallax)
//   - firewall   (this package — R145.C)
//   - honest     (R143)
//   - legal      (R166)
//   - lore       (R151 KAT-1 pin)
//   - manifest   (R150)
//   - mirrormark (L43 — placeholder signature surface today)
//   - persist    (x-poll quarry-db: FNV-1a 64-bit shard keys +
//                Beta-Binomial convergence engine for write-once
//                PostgreSQL receipt backing store)
//
// The R174 5-of-5 "core cohort" is: lore + mirrormark + manifest +
// honest + firewall. The demo adds 5 domain packages on top: chain +
// crosssdk + emitters + legal (R166) + persist (quarry-db x-poll).
func ExpectedPackages() []string {
	return []string{
		"chain",
		"crosssdk",
		"emitters",
		"firewall",
		"honest",
		"legal",
		"lore",
		"manifest",
		"mirrormark",
		"persist",
	}
}

// ExpectedR174CorePackages returns the 5 packages that constitute
// the R174 5-of-5 cohort-maturity discipline. The demo packages
// outside this set (chain + emitters + legal) are domain-specific
// additions.
func ExpectedR174CorePackages() []string {
	return []string{
		"firewall",
		"honest",
		"lore",
		"manifest",
		"mirrormark",
	}
}

func ExpectedBinaries() []string {
	return []string{
		"audit-chain-demo",
	}
}

func ScanInternal(repoRoot string) ([]string, error) {
	return scanGoSubtree(filepath.Join(repoRoot, "internal"))
}

func ScanCmd(repoRoot string) ([]string, error) {
	cmdDir := filepath.Join(repoRoot, "cmd")
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		mainGo := filepath.Join(cmdDir, e.Name(), "main.go")
		if _, err := os.Stat(mainGo); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func scanGoSubtree(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		hasGo, err := dirHasGoFile(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		if hasGo {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func dirHasGoFile(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) == ".go" {
			return true, nil
		}
	}
	return false, nil
}
