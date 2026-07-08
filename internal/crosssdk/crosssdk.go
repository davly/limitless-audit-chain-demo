// Package crosssdk is the FIRST real-import consumer wire-in for the
// R193 R-INFRA-WIRE-PROTOCOL-CONSUMER-EXTRACTION promotion ledger.
//
// # Why this package exists (W58 — 2026-05-29 R193 unblock)
//
// At I20 ship-time (2026-05-28 infra marathon) the limitless-audit-chain-
// demo flagship was the canonical 1st saturator of
// R-CROSS-INFRA-AUDIT-CHAIN-EMIT — but the I20 directive deliberately
// shipped the five emitter surfaces as `internal/emitters/` stand-ins
// labelled `// I20-STAND-IN`, NOT real `github.com/davly/{delve,grounded,
// recall,echo,parallax}-go` imports. The rationale at the time: those
// five SDKs were being uplifted in parallel.
//
// As of W16.A (2026-05-29) batch-9 ceremony plan, R193 promotion was
// flagged PROMOTION-BLOCKED because the cited consumers across the
// ecosystem all used stand-ins: verified consumer count was ZERO.
//
// W58's mandate: ship the SMALLEST honest wire-in that converts ≥1
// flagship into a verified-real consumer. This package is that ship.
//
// # What this package does
//
// It imports the SDK-side `cohort/lore` packages from THREE real
// upstream infrastructure SDKs:
//
//   - github.com/davly/recall-go/cohort/lore     (recall SDK)
//   - github.com/davly/grounded-go/cohort/lore   (grounded SDK)
//   - github.com/davly/delve-go/cohort/lore      (delve SDK)
//
// All three SDK lore packages pin the SAME ecosystem-canonical KAT-1
// HMAC-SHA256 digest (`239a7d0d…`). The function
// AssertCrossSubstrateKAT1Parity walks the three SDKs, calls each
// SDK's deterministic recomputation, and rejects if any drifts.
//
// This is the cohort R151 firewall pin re-stated at the SDK boundary
// — but importantly, the import edges are REAL: a regulator (or a
// Go-tooling audit) reading this demo's go.mod sees three honest
// `require github.com/davly/{recall,grounded,delve}-go vX.Y.Z` lines
// and three matching `import` directives in this file. The R155.A
// INDEX-LIE name-collision class (drift-cache / memo vocabulary
// borrowed from infra-nouns) is structurally inapplicable: we are
// importing the published Go modules, not local internal/ packages.
//
// # Why this is the smallest honest wire-in
//
// The five-emitter audit-chain pipeline at `internal/emitters/` still
// uses stand-ins — full per-emitter receipt surfaces are not yet
// stable across all five SDKs. But the cohort R151 KAT-1 invariant
// IS stable across all of them (it's been the cohort-wide firewall
// pin since 2026-05-22). So we wire in the SDK surface that's
// already production-quality: the KAT-1 firewall pin.
//
// One subcommand ("cross-substrate-kat1") added to the CLI demonstrates
// the wire-in to a customer-facing reader. The output is a 3-row
// PASS/FAIL table cross-checking each SDK's recomputed KAT-1 hex
// against the cohort canonical.
//
// # R193 ledger update
//
// Before W58 wire-in: 0 verified consumers.
// After W58 wire-in:  1 verified consumer (this flagship), 3 SDK
//                     consumer-import edges (recall-go + grounded-go +
//                     delve-go).
//
// R193 promotion is now READY-FOR-BATCH-9 per R193's "smallest honest
// wire-in" threshold.
package crosssdk

import (
	"fmt"
	"io"

	delvelore "github.com/davly/delve-go/cohort/lore"
	groundedlore "github.com/davly/grounded-go/cohort/lore"
	recalllore "github.com/davly/recall-go/cohort/lore"
)

// CohortCanonicalKAT1 is the ecosystem-wide canonical KAT-1
// HMAC-SHA256 hex digest. All cohort substrates pin to this string.
//
// Pinned byte-identical to:
//   - foundation/pkg/mirrormark.KAT1Digest
//   - github.com/davly/recall-go/cohort/lore.Digest
//   - github.com/davly/grounded-go/cohort/lore.Digest
//   - github.com/davly/delve-go/cohort/lore.Digest
//   - internal/lore.Digest (this flagship's local pin)
//
// Drift here breaks the cohort-wide trust chain. R151.
const CohortCanonicalKAT1 = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

// SDKCheck is a per-SDK cross-substrate KAT-1 parity check result.
type SDKCheck struct {
	// SDK is the human-readable SDK identifier (e.g. "recall-go").
	SDK string

	// ImportPath is the canonical Go import path for the SDK's
	// cohort/lore package (e.g. "github.com/davly/recall-go/cohort/lore").
	ImportPath string

	// PinnedHex is the digest the SDK's `Digest` constant declares.
	PinnedHex string

	// RecomputedHex is the value the SDK's recomputation function
	// produces by running stdlib HMAC-SHA256 over the canonical KAT-1
	// input + empty key.
	RecomputedHex string

	// Pass is true iff PinnedHex == RecomputedHex == CohortCanonicalKAT1.
	Pass bool
}

// AllSDKChecks walks the three real-import SDKs and returns the
// per-SDK parity check. Pure deterministic — no network calls.
//
// Returns the ordered slice (recall, grounded, delve) so the output
// is reproducible across runs.
func AllSDKChecks() []SDKCheck {
	return []SDKCheck{
		{
			SDK:           "recall-go",
			ImportPath:    "github.com/davly/recall-go/cohort/lore",
			PinnedHex:     recalllore.Digest,
			RecomputedHex: recalllore.ComputeKAT1(),
			Pass:          recalllore.Digest == CohortCanonicalKAT1 && recalllore.AssertKAT1Parity(),
		},
		{
			SDK:           "grounded-go",
			ImportPath:    "github.com/davly/grounded-go/cohort/lore",
			PinnedHex:     groundedlore.Digest,
			RecomputedHex: groundedlore.ComputeKAT1(),
			Pass:          groundedlore.Digest == CohortCanonicalKAT1 && groundedlore.AssertKAT1Parity(),
		},
		{
			SDK:           "delve-go",
			ImportPath:    "github.com/davly/delve-go/cohort/lore",
			PinnedHex:     delvelore.Digest,
			RecomputedHex: delvelore.ComputeKAT1(),
			Pass:          delvelore.Digest == CohortCanonicalKAT1 && delvelore.AssertKAT1Parity(),
		},
	}
}

// AssertCrossSubstrateKAT1Parity returns nil iff every SDK in the
// closed-set cohort pins the same KAT-1 hex AND recomputes to the
// same hex. Drift returns a descriptive error naming the first
// failing SDK.
//
// Used by `cmd/audit-chain-demo cross-substrate-kat1` to gate
// process exit on parity.
func AssertCrossSubstrateKAT1Parity() error {
	for _, c := range AllSDKChecks() {
		if c.PinnedHex != CohortCanonicalKAT1 {
			return fmt.Errorf("R151 FIREWALL DRIFT: %s pins %s, cohort canonical is %s",
				c.SDK, c.PinnedHex, CohortCanonicalKAT1)
		}
		if c.RecomputedHex != CohortCanonicalKAT1 {
			return fmt.Errorf("R151 FIREWALL DRIFT: %s recomputes %s, cohort canonical is %s",
				c.SDK, c.RecomputedHex, CohortCanonicalKAT1)
		}
		if !c.Pass {
			return fmt.Errorf("R151 FIREWALL DRIFT: %s composite parity check failed", c.SDK)
		}
	}
	return nil
}

// PrintReport writes a regulator-grade parity table to w. The output
// is grep-friendly (one row per SDK + an overall PASS/FAIL line).
func PrintReport(w io.Writer) error {
	checks := AllSDKChecks()
	fmt.Fprintf(w, "R193 cross-substrate KAT-1 parity (W58 wire-in)\n\n")
	fmt.Fprintf(w, "  Cohort canonical: %s\n\n", CohortCanonicalKAT1)
	fmt.Fprintf(w, "  %-14s  %-50s  %s\n", "SDK", "Import path", "Status")
	fmt.Fprintf(w, "  %-14s  %-50s  %s\n", "---", "-----------", "------")
	for _, c := range checks {
		status := "FAIL"
		if c.Pass {
			status = "PASS"
		}
		fmt.Fprintf(w, "  %-14s  %-50s  %s\n", c.SDK, c.ImportPath, status)
	}
	fmt.Fprintln(w)
	if err := AssertCrossSubstrateKAT1Parity(); err != nil {
		fmt.Fprintf(w, "OVERALL: FAIL — %v\n", err)
		return err
	}
	fmt.Fprintf(w, "OVERALL: PASS (3/3 SDKs cross-substrate parity verified)\n")
	return nil
}
