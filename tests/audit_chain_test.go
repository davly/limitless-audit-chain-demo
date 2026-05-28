// Package tests holds the end-to-end audit-chain pipeline test for
// limitless-audit-chain-demo — the canonical R-CROSS-INFRA-AUDIT-
// CHAIN-EMIT 1st-saturator showcase.
package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/davly/limitless-audit-chain-demo/internal/chain"
	"github.com/davly/limitless-audit-chain-demo/internal/emitters"
)

// TestEndToEnd_FiveStepPipelineVerifiesChain runs the canonical
// 5-step pipeline (delve -> grounded -> recall -> echo -> parallax)
// and asserts the resulting chain verifies under MirrorMarkVerifier.
//
// This is the load-bearing showcase test — if this passes, the
// R-CROSS-INFRA-AUDIT-CHAIN-EMIT first-saturator claim is honest.
func TestEndToEnd_FiveStepPipelineVerifiesChain(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	step := time.Second

	c := &chain.Chain{}

	// Step 1: delve schema-card.
	p1 := []byte(`{"schema":"audit_event"}`)
	r1 := emitters.EmitDelveReceipt(p1, chain.GenesisPrevHash, t0)
	c.Append(r1)

	// Step 2: grounded citation.
	p2 := []byte(`{"citation":"R-CROSS-INFRA-AUDIT-CHAIN-EMIT"}`)
	r2 := emitters.EmitGroundedReceipt(p2, r1.Hash(), t0.Add(step))
	c.Append(r2)

	// Step 3: recall cache.
	p3 := []byte(`{"cache":"hit"}`)
	r3 := emitters.EmitRecallReceipt(p3, r2.Hash(), t0.Add(2*step))
	c.Append(r3)

	// Step 4: echo event.
	p4 := []byte(`{"event":"citation.lookup"}`)
	r4 := emitters.EmitEchoReceipt(p4, r3.Hash(), t0.Add(3*step))
	c.Append(r4)

	// Step 5: parallax job dispatch.
	p5 := []byte(`{"job":"process"}`)
	r5 := emitters.EmitParallaxReceipt(p5, r4.Hash(), t0.Add(4*step))
	c.Append(r5)

	if c.Len() != 5 {
		t.Fatalf("chain length: got %d, want 5", c.Len())
	}

	verifier := emitters.MirrorMarkVerifier()
	if err := c.Verify(verifier); err != nil {
		t.Fatalf("end-to-end chain.Verify: %v", err)
	}

	wantOrder := []chain.SignerID{
		chain.SignerDelve, chain.SignerGrounded, chain.SignerRecall,
		chain.SignerEcho, chain.SignerParallax,
	}
	got := c.SignerSequence()
	for i, want := range wantOrder {
		if got[i] != want {
			t.Fatalf("step %d: got %s, want %s", i+1, got[i], want)
		}
	}

	// Confirm each receipt's PayloadHash deterministically matches
	// the SHA-256 of its emitted payload.
	payloads := [][]byte{p1, p2, p3, p4, p5}
	for i, p := range payloads {
		sum := sha256.Sum256(p)
		want := hex.EncodeToString(sum[:])
		if c.Receipts[i].PayloadHash != want {
			t.Fatalf("step %d PayloadHash drift:\n  got:  %s\n  want: %s",
				i+1, c.Receipts[i].PayloadHash, want)
		}
	}
}

// TestEndToEnd_TamperingMiddleReceiptBreaksChain confirms the
// tamper-evidence property — substituting a middle receipt's payload
// after the next receipt has captured its hash MUST fail Verify.
func TestEndToEnd_TamperingMiddleReceiptBreaksChain(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	step := time.Second
	c := &chain.Chain{}

	r1 := emitters.EmitDelveReceipt([]byte("p1"), chain.GenesisPrevHash, t0)
	c.Append(r1)
	r2 := emitters.EmitGroundedReceipt([]byte("p2"), r1.Hash(), t0.Add(step))
	c.Append(r2)
	r3 := emitters.EmitRecallReceipt([]byte("p3"), r2.Hash(), t0.Add(2*step))
	c.Append(r3)

	// Tamper with the middle receipt: re-sign with a different
	// payload AFTER r3 captured r2's hash.
	tampered := emitters.EmitGroundedReceipt([]byte("p2-evil"), r1.Hash(), t0.Add(step))
	c.Receipts[1] = tampered

	verifier := emitters.MirrorMarkVerifier()
	if err := c.Verify(verifier); err == nil {
		t.Fatalf("tampered chain unexpectedly verified")
	}
}

// TestEndToEnd_SwappingSignerBreaksChain confirms that swapping a
// receipt's SignerID without re-signing fails verification — the
// per-emitter corpus tag binds signatures to their signer.
func TestEndToEnd_SwappingSignerBreaksChain(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	step := time.Second
	c := &chain.Chain{}

	r1 := emitters.EmitDelveReceipt([]byte("p1"), chain.GenesisPrevHash, t0)
	c.Append(r1)
	r2 := emitters.EmitGroundedReceipt([]byte("p2"), r1.Hash(), t0.Add(step))
	c.Append(r2)

	// Swap r2's SignerID without re-signing.
	c.Receipts[1].SignerID = chain.SignerEcho

	verifier := emitters.MirrorMarkVerifier()
	if err := c.Verify(verifier); err == nil {
		t.Fatalf("signer-swap chain unexpectedly verified")
	}
}

// TestEndToEnd_ChainPrintsHumanReadableTimeline exercises the
// canonical timeline-view helper used by audit-export surfaces.
func TestEndToEnd_ChainPrintsHumanReadableTimeline(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	step := time.Second
	c := &chain.Chain{}
	r1 := emitters.EmitDelveReceipt([]byte("a"), chain.GenesisPrevHash, t0)
	c.Append(r1)
	r2 := emitters.EmitGroundedReceipt([]byte("b"), r1.Hash(), t0.Add(step))
	c.Append(r2)

	sorted := c.SortedReceiptsCopy()
	if len(sorted) != 2 {
		t.Fatalf("sorted length: got %d, want 2", len(sorted))
	}
	if !sorted[0].Timestamp.Before(sorted[1].Timestamp) {
		t.Fatalf("sorted chain not ascending by timestamp")
	}
}

// TestEndToEnd_ReceiptSignaturesAreLoreV1MirrorMarks confirms every
// step's signature has the cohort Mirror-Mark format prefix.
func TestEndToEnd_ReceiptSignaturesAreLoreV1MirrorMarks(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	step := time.Second
	c := &chain.Chain{}
	r1 := emitters.EmitDelveReceipt([]byte("a"), chain.GenesisPrevHash, t0)
	c.Append(r1)
	r2 := emitters.EmitGroundedReceipt([]byte("b"), r1.Hash(), t0.Add(step))
	c.Append(r2)
	r3 := emitters.EmitRecallReceipt([]byte("c"), r2.Hash(), t0.Add(2*step))
	c.Append(r3)
	r4 := emitters.EmitEchoReceipt([]byte("d"), r3.Hash(), t0.Add(3*step))
	c.Append(r4)
	r5 := emitters.EmitParallaxReceipt([]byte("e"), r4.Hash(), t0.Add(4*step))
	c.Append(r5)

	for i, r := range c.Receipts {
		if !strings.HasPrefix(r.Signature, "lore@v1:") {
			t.Fatalf("receipt[%d] signature missing lore@v1: prefix: %q", i, r.Signature)
		}
	}
}
