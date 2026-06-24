// Command audit-chain-demo runs the canonical 5-step cross-infra
// audit-chain pipeline + verifies the resulting chain.
//
// This is the SHOWCASE artefact for R-CROSS-INFRA-AUDIT-CHAIN-EMIT.
//
// Subcommands:
//
//	run [--expect-tip H] Run the 5-step pipeline + print the chain + verify;
//	                     with --expect-tip, also assert the chain ends at hex
//	                     tip H (cold-verify tail-truncation / removal guard)
//	advisories           List R143 honest advisories (cohort discipline reminders)
//	footer               Print the founder-drafted legal footer (R166)
//	kat1                 Print KAT-1 cohort hex + OpenSSL cold-verify recipe
//	manifest             Print the R150 manifest entries
//	version              Print the demo's version string
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/davly/limitless-audit-chain-demo/internal/chain"
	"github.com/davly/limitless-audit-chain-demo/internal/emitters"
	"github.com/davly/limitless-audit-chain-demo/internal/honest"
	"github.com/davly/limitless-audit-chain-demo/internal/legal"
	"github.com/davly/limitless-audit-chain-demo/internal/lore"
	"github.com/davly/limitless-audit-chain-demo/internal/manifest"
)

const version = "0.1.0-I20-1st-saturator"

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: audit-chain-demo <command> [flags]

Commands:
  run [--expect-tip H] Run the 5-step pipeline + print + verify the chain;
                       with --expect-tip, also assert the chain ends at hex
                       tip H (cold-verify truncation / receipt-removal guard)
  advisories           List R143 honest advisories
  footer               Print the founder-drafted legal footer
  kat1                 Print KAT-1 cohort hex + OpenSSL cold-verify recipe
  manifest             Print the R150 manifest entries
  version              Print the demo's version string
  help                 Print this help

R-CROSS-INFRA-AUDIT-CHAIN-EMIT (1st saturator):
  This demo composes signed receipts from five upstream emitters
  (delve -> grounded -> recall -> echo -> parallax) into a single
  tamper-evident chain. See README.md + CONTEXT.md.`)
}

func main() {
	// Boot-time R143 LOUD-ONCE-WARN advisories — print all three on
	// stderr so a regulator-grade reader sees the demo cohort
	// discipline reminders before any pipeline output.
	for _, adv := range honest.CanonicalAdvisories() {
		honest.LoudOnce(adv, os.Stderr)
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	rest := os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)

	switch cmd {
	case "version", "--version", "-V":
		fmt.Printf("audit-chain-demo %s\n", version)

	case "run":
		expectTip := fs.String("expect-tip", "", "if set, additionally assert the chain ends at this hex tip hash (cold-verify truncation guard); see VerifyToTip")
		_ = fs.Parse(rest)
		if err := runDemo(os.Stdout, *expectTip); err != nil {
			fmt.Fprintf(os.Stderr, "demo run: %v\n", err)
			os.Exit(3)
		}

	case "advisories":
		_ = fs.Parse(rest)
		advs := honest.CanonicalAdvisories()
		fmt.Printf("audit-chain-demo canonical R143 advisories (%d):\n\n", len(advs))
		for _, a := range advs {
			fmt.Printf("  [%s] %s\n      %s\n      (see %s)\n\n", a.Severity, a.Code, a.Message, a.DocLink)
		}

	case "footer":
		_ = fs.Parse(rest)
		fmt.Print(legal.DemoLiabilityFooter)

	case "kat1":
		_ = fs.Parse(rest)
		fmt.Println("audit-chain-demo KAT-1 cohort firewall pin (R151)")
		fmt.Println()
		fmt.Printf("  Cohort canonical hex (HMAC-SHA256 of 0x01||32x0x00 with empty key):\n")
		fmt.Printf("    %s\n\n", lore.Digest)
		fmt.Printf("  Recomputed on this machine via Go crypto/hmac:\n")
		fmt.Printf("    %s\n\n", lore.Compute())
		if lore.Digest != lore.Compute() {
			fmt.Fprintln(os.Stderr, "R151 FIREWALL DRIFT: cohort hex != recomputed hex")
			os.Exit(3)
		}
		fmt.Println("  Cold-verify via OpenSSL (no Go toolchain required):")
		fmt.Println(`    printf '\x01' > /tmp/kat1.bin`)
		fmt.Print(`    printf '\x00`)
		fmt.Print("%")
		fmt.Println(`.0s' {1..32} >> /tmp/kat1.bin`)
		fmt.Println(`    openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin`)
		fmt.Println()
		fmt.Println("  PASS: KAT-1 matches cohort canonical hex.")

	case "manifest":
		_ = fs.Parse(rest)
		m := manifest.Seed()
		fmt.Printf("audit-chain-demo R150 manifest (%d entries):\n\n", len(m))
		for _, e := range m {
			counselMark := "[founder-draft]"
			if e.ReviewedByCounsel {
				counselMark = "[counsel-reviewed]"
			}
			fmt.Printf("  %s  %s\n      jurisdiction: %s\n      source:       %s\n      reviewer:     %s\n      fresh-at:     %s\n\n",
				counselMark, e.Key, e.Jurisdiction, e.Source, e.ReviewerClass, e.FreshAt.Format("2006-01-02"))
		}

	case "--help", "-h", "help":
		usage()

	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

// runDemo executes the canonical 5-step pipeline:
//
//	Step 1: delve emits a schema-card receipt (R1, genesis).
//	Step 2: grounded emits a citation receipt (R2, chains R1).
//	Step 3: recall emits a cache receipt (R3, chains R2).
//	Step 4: echo emits an event receipt (R4, chains R3).
//	Step 5: parallax emits a job dispatch receipt (R5, chains R4).
//
// Returns nil iff the chain verifies under MirrorMarkVerifier.
//
// If expectTipHash is non-empty, runDemo ADDITIONALLY asserts the
// chain ends at that hex tip hash via chain.VerifyToTip — the
// cold-verify recipe for detecting tail-truncation / receipt-removal.
// A regulator handed "a chain that must end at receipt H" runs
// `audit-chain-demo run --expect-tip H`; a truncated chain fails with
// ErrTipMismatch even though plain Verify would pass.
func runDemo(out *os.File, expectTipHash string) error {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	step := time.Second

	c := &chain.Chain{}

	// Step 1: delve emits a schema-card receipt.
	delvePayload := []byte(`{"schema":"audit_event","cols":["actor","ts","payload_sha256"],"version":1}`)
	r1 := emitters.EmitDelveReceipt(delvePayload, chain.GenesisPrevHash, t0)
	c.Append(r1)

	// Step 2: grounded retrieves a citation from a corpus.
	groundedPayload := []byte(`{"citation":"R-CROSS-INFRA-AUDIT-CHAIN-EMIT","corpus_sha256":"abc...","section":"part-xii"}`)
	r2 := emitters.EmitGroundedReceipt(groundedPayload, r1.Hash(), t0.Add(step))
	c.Append(r2)

	// Step 3: recall caches the citation lookup.
	recallPayload := []byte(`{"key":"corpus_sha256:abc...","value_sha256":"def...","ttl_s":3600}`)
	r3 := emitters.EmitRecallReceipt(recallPayload, r2.Hash(), t0.Add(2*step))
	c.Append(r3)

	// Step 4: echo emits an event capturing the lookup result.
	echoPayload := []byte(`{"event":"citation.lookup","outcome":"hit","latency_ms":3}`)
	r4 := emitters.EmitEchoReceipt(echoPayload, r3.Hash(), t0.Add(3*step))
	c.Append(r4)

	// Step 5: parallax dispatches a job to process the event.
	parallaxPayload := []byte(`{"job":"citation.process","handler":"limitless.audit","priority":"normal"}`)
	r5 := emitters.EmitParallaxReceipt(parallaxPayload, r4.Hash(), t0.Add(4*step))
	c.Append(r5)

	fmt.Fprintf(out, "R-CROSS-INFRA-AUDIT-CHAIN-EMIT — 5-step pipeline\n\n")
	for i, r := range c.Receipts {
		fmt.Fprintf(out, "  [R%d] signer=%-10s payload_hash=%s\n",
			i+1, r.SignerID, r.PayloadHash[:16]+"...")
		fmt.Fprintf(out, "       prev_hash   =%s\n", short(r.PrevReceiptHash))
		fmt.Fprintf(out, "       timestamp   =%s\n", r.Timestamp.UTC().Format(time.RFC3339))
		fmt.Fprintf(out, "       signature   =%s\n\n", short(r.Signature))
	}

	verifier := emitters.MirrorMarkVerifier()
	if err := c.Verify(verifier); err != nil {
		return fmt.Errorf("chain Verify: %w", err)
	}
	fmt.Fprintf(out, "Chain verification: PASS  (5/5 receipts verified, 4/4 prev-hash links intact)\n")
	fmt.Fprintf(out, "Signer sequence: %v\n", c.SignerSequence())

	// The genuine tip hash (R5) — the value a cold-verifier would be
	// handed out-of-band and feed back via --expect-tip.
	tip := c.Receipts[len(c.Receipts)-1].Hash()
	fmt.Fprintf(out, "Chain tip (R5 hash): %s\n", tip)

	if expectTipHash != "" {
		if err := c.VerifyToTip(verifier, expectTipHash); err != nil {
			return fmt.Errorf("chain VerifyToTip (truncation guard): %w", err)
		}
		fmt.Fprintf(out, "Tip assertion: PASS  (chain ends at expected tip — no tail-truncation)\n")
	}
	return nil
}

func short(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:16] + "..." + s[len(s)-4:]
}
