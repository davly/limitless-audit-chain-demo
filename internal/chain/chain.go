// Package chain is the composition library that turns N independent
// signed receipts into a single tamper-evident audit chain — the
// load-bearing primitive behind R-CROSS-INFRA-AUDIT-CHAIN-EMIT.
//
// # Why this package exists (R-CROSS-INFRA-AUDIT-CHAIN-EMIT canonical demo)
//
// The Limitless cohort ships ~five infrastructure flagships that each
// emit signed receipts at trust boundaries:
//
//   - delve     — emits a receipt when a schema-card lands at a
//     database boundary.
//   - grounded  — emits a receipt when a citation is retrieved from
//     an authoritative corpus.
//   - recall    — emits a receipt when a citation lookup is cached.
//   - echo      — emits a receipt when an event is published.
//   - parallax  — emits a receipt when a job is dispatched.
//
// Individually each receipt is sound: an OpenSSL one-liner with the
// signer's public verification material proves "this signer attested
// to this payload at this time." But a regulator (or an auditor, or
// a downstream tenant) reading a single receipt cannot answer "what
// caused this?" The receipts are atomic, not composable.
//
// R-CROSS-INFRA-AUDIT-CHAIN-EMIT (1st saturator: this demo) is the
// discipline of:
//
//  1. Each emitter includes a `prev_receipt_hash` field in its
//     payload, chosen as the SHA-256 over the canonical bytes of the
//     immediately-preceding receipt in the pipeline.
//  2. The receipts form a strictly-ordered sequence — receipt R_i
//     is the cryptographic descendant of receipt R_{i-1}.
//  3. The chain is bottom-up verifiable: a verifier walks from R_1
//     forward, recomputing each prev_receipt_hash and re-verifying
//     each signature, and rejects the chain if ANY step fails.
//
// Tampering with any receipt in the middle of the chain breaks
// either (a) the signature on that receipt (if the payload was
// edited) or (b) the prev-hash on the next receipt (if the receipt
// was substituted). The chain is therefore tamper-evident as a
// composite even though each individual receipt is independently
// signed by a different emitter.
//
// # Truncation is detectable only with an expected tip
//
// The signed canonical bytes (Receipt.CanonicalBytes) commit to
// payload_hash, prev_receipt_hash, signer_id and timestamp ONLY —
// there is no sequence index, no chain-length commitment, and no
// tip/last-receipt marker. Consequently plain Verify, while it
// catches middle-of-chain tamper, CANNOT detect that the trailing
// receipts were silently removed: an adversary holding a valid
// N-receipt chain can drop the last receipt(s) (e.g. the parallax
// job-dispatch record of what happened last) and the shorter chain
// still passes Verify — genesis intact, every prev-hash links, every
// signature verifies. This is the classic append-only-log truncation
// gap. To close it for a cold-verify workflow, the verifier must know
// the chain's expected endpoint out-of-band: use VerifyToTip (assert
// the chain ends at a known receipt hash) or VerifyN (assert the
// chain has a known length), which return ErrTipMismatch /
// ErrLengthMismatch on truncation. Plain Verify remains correct for
// callers who legitimately hold a variable-length chain.
//
// # Honest scope
//
// This package implements the chain composition primitive only — it
// does NOT verify the upstream signatures. Each receipt carries a
// signer-id and a payload-hash; the chain layer enforces the
// prev-receipt-hash linkage. Substrate signature verification is the
// responsibility of the individual emitter SDKs (delve / grounded /
// recall / echo / parallax) whose public verification interfaces
// the demo's `internal/emitters/` package stands in for at I20 ship.
//
// At I20 ship, signature verification uses the cohort's Mirror-Mark
// HMAC primitive (`internal/mirrormark`) as a placeholder — when the
// five upstream SDKs land their respective signature surfaces, the
// chain verifier will dispatch on Receipt.SignerID to the matching
// verifier. The dispatch is a one-line table-driven swap.
package chain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SignerID identifies which upstream emitter signed the receipt.
//
// The five canonical signer IDs match the five I20 pipeline steps.
type SignerID string

const (
	SignerDelve    SignerID = "delve"
	SignerGrounded SignerID = "grounded"
	SignerRecall   SignerID = "recall"
	SignerEcho     SignerID = "echo"
	SignerParallax SignerID = "parallax"
)

// AllSignerIDs returns the closed-set cohort of recognised signers.
func AllSignerIDs() []SignerID {
	return []SignerID{SignerDelve, SignerGrounded, SignerRecall, SignerEcho, SignerParallax}
}

// IsKnownSignerID returns true if s is in the closed-set cohort.
func IsKnownSignerID(s SignerID) bool {
	for _, k := range AllSignerIDs() {
		if k == s {
			return true
		}
	}
	return false
}

// Receipt is a single signed step in the cross-infra audit chain.
//
// Wire format (sorted-key, newline-delimited UTF-8):
//
//	prev_receipt_hash: <hex SHA-256 of preceding receipt's canonical bytes, or 64-char "0" string for genesis>
//	payload_hash: <hex SHA-256 of the emitter's payload bytes>
//	signer_id: <one of: delve | grounded | recall | echo | parallax>
//	timestamp: <RFC3339 UTC>
//
// The Signature field is computed OVER the canonical bytes above by
// the emitter's signing primitive (Mirror-Mark today; per-emitter
// signature in a follow-up M-slot). The chain verifier RE-derives
// the canonical bytes from the four fields and feeds them to the
// signature verifier.
type Receipt struct {
	// PrevReceiptHash is the hex-encoded SHA-256 over the canonical
	// bytes of the immediately-preceding Receipt in the chain.
	//
	// For the genesis receipt (no predecessor), this is the
	// 64-character string of '0' digits — a sentinel chosen to be
	// distinct from any real SHA-256 output AND grep-discoverable.
	PrevReceiptHash string

	// PayloadHash is the hex-encoded SHA-256 over the emitter's
	// domain-specific payload bytes (e.g. delve's schema-card,
	// grounded's citation, recall's cache entry, etc.).
	//
	// The chain layer does NOT inspect the payload itself — it only
	// commits to the payload's hash. The emitter SDK is responsible
	// for binding the payload bytes back to the hash on the verify
	// side.
	PayloadHash string

	// SignerID identifies which emitter signed this receipt.
	SignerID SignerID

	// Timestamp is the UTC RFC3339 time at which the receipt was
	// signed.
	Timestamp time.Time

	// Signature is the emitter's signature over the canonical bytes
	// of (PrevReceiptHash, PayloadHash, SignerID, Timestamp).
	//
	// At I20 ship, Signature is a Mirror-Mark (cohort HMAC-SHA256
	// receipt) computed by the chain layer's KAT-1 keying. When the
	// five upstream SDKs land their per-signer signature surfaces,
	// the chain verifier will dispatch on SignerID.
	Signature string
}

// GenesisPrevHash is the 64-character sentinel used as the
// PrevReceiptHash of a chain's first receipt. Chosen distinct from
// any real SHA-256 output (all-zero hex is also valid SHA-256 output
// in principle, but the cohort uses '0'×64 specifically as a
// "no-predecessor" signal that is grep-discoverable in audit logs).
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// CanonicalBytes returns the deterministic, sort-stable, newline-
// delimited UTF-8 representation of the receipt's signed fields.
//
// The signer hashes / signs OVER these bytes. The verifier
// re-derives these bytes from the stored Receipt + feeds them to
// the signature verifier. Bit-equal across emitter implementations.
//
// Field ordering is alphabetical-stable.
func (r Receipt) CanonicalBytes() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "payload_hash: %s\n", r.PayloadHash)
	fmt.Fprintf(&b, "prev_receipt_hash: %s\n", r.PrevReceiptHash)
	fmt.Fprintf(&b, "signer_id: %s\n", r.SignerID)
	fmt.Fprintf(&b, "timestamp: %s\n", r.Timestamp.UTC().Format(time.RFC3339))
	return []byte(b.String())
}

// Hash returns the hex-encoded SHA-256 of the receipt's canonical
// bytes. This is the value the NEXT receipt in the chain stores in
// its PrevReceiptHash field.
func (r Receipt) Hash() string {
	sum := sha256.Sum256(r.CanonicalBytes())
	return hex.EncodeToString(sum[:])
}

// IsGenesis returns true when r is the first receipt in a chain
// (PrevReceiptHash = GenesisPrevHash).
func (r Receipt) IsGenesis() bool {
	return r.PrevReceiptHash == GenesisPrevHash
}

// Chain is an ordered sequence of Receipts forming a verifiable
// audit trail across the five-emitter pipeline.
type Chain struct {
	Receipts []Receipt
}

// Append adds a receipt to the chain. The caller is responsible for
// setting the receipt's PrevReceiptHash correctly — the chain layer
// does NOT compute it automatically. (The cohort discipline: the
// emitter computes the prev-hash from the parent receipt visible to
// it at signing time — the chain is the verifier, not the builder.)
func (c *Chain) Append(r Receipt) {
	c.Receipts = append(c.Receipts, r)
}

// Len returns the chain length.
func (c *Chain) Len() int { return len(c.Receipts) }

// ErrEmptyChain — Verify called on a zero-length chain.
var ErrEmptyChain = errors.New("chain: empty chain (nothing to verify)")

// ErrGenesisPrevHash — first receipt's PrevReceiptHash is not the
// canonical sentinel.
var ErrGenesisPrevHash = errors.New("chain: first receipt PrevReceiptHash must be the genesis sentinel")

// ErrPrevHashMismatch — non-genesis receipt's PrevReceiptHash does
// not equal the predecessor's computed Hash.
var ErrPrevHashMismatch = errors.New("chain: prev_receipt_hash does not match predecessor's Hash()")

// ErrUnknownSigner — receipt's SignerID is not in the closed-set
// cohort.
var ErrUnknownSigner = errors.New("chain: unknown SignerID (not in closed-set cohort)")

// ErrTimestampInverted — receipt's Timestamp is earlier than the
// predecessor's.
var ErrTimestampInverted = errors.New("chain: receipt timestamp earlier than predecessor (chain is not temporally ordered)")

// ErrEmptySignature — receipt is missing its signature.
var ErrEmptySignature = errors.New("chain: receipt missing signature")

// ErrSignatureMismatch — receipt's signature did not verify under
// the supplied verifier.
var ErrSignatureMismatch = errors.New("chain: signature did not verify")

// ErrTipMismatch — the chain's last receipt Hash() does not equal the
// expected tip supplied to VerifyToTip. This is the truncation /
// receipt-removal guard: a structurally-valid chain whose trailing
// receipts have been dropped passes plain Verify (genesis intact,
// every prev-hash links, every signature verifies) but FAILS
// VerifyToTip when the verifier was told the chain must end at a
// specific receipt hash.
var ErrTipMismatch = errors.New("chain: chain tip does not match expected tip (possible tail-truncation / receipt-removal)")

// ErrLengthMismatch — the chain's length does not equal the expected
// length supplied to VerifyN. The length-pinned sibling of
// ErrTipMismatch for callers who were handed an expected receipt
// count rather than a tip hash.
var ErrLengthMismatch = errors.New("chain: chain length does not match expected length (possible tail-truncation / receipt-removal)")

// VerifierFunc verifies the signature of a single receipt. The
// chain library calls this once per receipt, in order, during Verify.
//
// The default verifier (DefaultMirrorMarkVerifier) checks the
// Mirror-Mark HMAC-SHA256 signature using the demo's KAT-1 keying.
// A future M-slot will introduce a dispatch verifier that selects
// the per-signer signature surface based on Receipt.SignerID.
type VerifierFunc func(r Receipt) error

// Verify walks the chain bottom-up (genesis to tip) and rejects on
// the first failure. Returns nil iff every receipt is structurally
// valid AND every prev-hash link is recomputed-matching AND every
// signature verifies under verifier.
//
// Bottom-up (chronological) walk — the cohort discipline names this
// "bottom-up" because the chain is a tree whose leaves are the
// emitter outputs at the wire and whose root is the genesis. We
// walk from root → leaves, which is bottom-to-top of the trust
// hierarchy (the genesis is the trust anchor).
func (c *Chain) Verify(verifier VerifierFunc) error {
	if len(c.Receipts) == 0 {
		return ErrEmptyChain
	}
	if c.Receipts[0].PrevReceiptHash != GenesisPrevHash {
		return ErrGenesisPrevHash
	}
	for i, r := range c.Receipts {
		if !IsKnownSignerID(r.SignerID) {
			return fmt.Errorf("%w: receipt[%d].SignerID=%q", ErrUnknownSigner, i, r.SignerID)
		}
		if r.Signature == "" {
			return fmt.Errorf("%w: receipt[%d]", ErrEmptySignature, i)
		}
		if i > 0 {
			parent := c.Receipts[i-1]
			expected := parent.Hash()
			if r.PrevReceiptHash != expected {
				return fmt.Errorf("%w: receipt[%d].PrevReceiptHash=%s, expected=%s",
					ErrPrevHashMismatch, i, r.PrevReceiptHash, expected)
			}
			if r.Timestamp.Before(parent.Timestamp) {
				return fmt.Errorf("%w: receipt[%d].Timestamp=%s, parent=%s",
					ErrTimestampInverted, i,
					r.Timestamp.UTC().Format(time.RFC3339),
					parent.Timestamp.UTC().Format(time.RFC3339))
			}
		}
		if err := verifier(r); err != nil {
			return fmt.Errorf("%w: receipt[%d] signer=%s: %v",
				ErrSignatureMismatch, i, r.SignerID, err)
		}
	}
	return nil
}

// VerifyToTip runs the full Verify walk AND additionally asserts that
// the chain ends at the receipt whose Hash() equals expectedTipHash.
//
// # Why this exists (the tail-truncation guard)
//
// Plain Verify proves every receipt is structurally valid, every
// prev-hash links forward, and every signature verifies — but it
// CANNOT detect that trailing receipts were silently removed. The
// signed canonical bytes (CanonicalBytes) commit to payload_hash,
// prev_receipt_hash, signer_id and timestamp only — there is no
// sequence index, no chain-length commitment, and no tip marker. So
// an adversary holding a valid N-receipt chain can drop the trailing
// receipts (e.g. the last parallax job-dispatch record) and the
// shorter chain still passes Verify with zero errors: genesis intact,
// every prev-hash links, every signature still verifies. For an
// append-only audit log this is the classic truncation gap.
//
// VerifyToTip closes that gap for the cold-verify workflow: a
// regulator (or any verifier) who was handed "a chain that must end
// at receipt H" passes H as expectedTipHash; if the chain was
// truncated, the recomputed tip no longer matches H and VerifyToTip
// returns ErrTipMismatch. Callers who genuinely hold a
// variable-length chain (and have no out-of-band tip) keep using
// plain Verify — this method is strictly additive and changes no
// wire-format, signature, or canonical-bytes behaviour.
//
// Returns the same errors as Verify on a structurally-invalid chain,
// plus ErrEmptyChain when the chain is empty and ErrTipMismatch when
// the (structurally-valid) chain's tip does not equal expectedTipHash.
func (c *Chain) VerifyToTip(verifier VerifierFunc, expectedTipHash string) error {
	if err := c.Verify(verifier); err != nil {
		return err
	}
	// Verify guarantees len(c.Receipts) > 0 here (empty chains return
	// ErrEmptyChain above), so indexing the tip is safe.
	gotTip := c.Receipts[len(c.Receipts)-1].Hash()
	// hmac.Equal is used for uniformity with the cohort's
	// constant-time comparison idiom even though both operands are
	// public hex hashes (no secret-dependent timing here).
	if !hmac.Equal([]byte(gotTip), []byte(expectedTipHash)) {
		return fmt.Errorf("%w: got tip=%s, expected=%s", ErrTipMismatch, gotTip, expectedTipHash)
	}
	return nil
}

// VerifyN runs the full Verify walk AND additionally asserts that the
// chain contains exactly wantLen receipts.
//
// This is the length-pinned sibling of VerifyToTip for the cold-verify
// workflow where the regulator was handed "a chain of exactly N
// receipts" rather than a tip hash. It catches the same
// tail-truncation / receipt-removal gap (plain Verify is blind to a
// dropped trailing receipt) via the chain-length commitment the wire
// format does not carry. Strictly additive; no wire-format change.
//
// Returns the same errors as Verify on a structurally-invalid chain,
// plus ErrLengthMismatch when the (structurally-valid) chain's length
// does not equal wantLen.
func (c *Chain) VerifyN(verifier VerifierFunc, wantLen int) error {
	if err := c.Verify(verifier); err != nil {
		return err
	}
	if got := len(c.Receipts); got != wantLen {
		return fmt.Errorf("%w: got length=%d, expected=%d", ErrLengthMismatch, got, wantLen)
	}
	return nil
}

// SignerSequence returns the signer IDs in append order — used by
// tests + the CLI to assert pipeline order without exposing the
// full receipt bodies.
func (c *Chain) SignerSequence() []SignerID {
	out := make([]SignerID, 0, len(c.Receipts))
	for _, r := range c.Receipts {
		out = append(out, r.SignerID)
	}
	return out
}

// SortedReceiptsCopy returns a defensive copy of the chain's
// receipts sorted by Timestamp ascending. Used by audit-export
// surfaces that emit a canonical timeline view.
func (c *Chain) SortedReceiptsCopy() []Receipt {
	out := make([]Receipt, len(c.Receipts))
	copy(out, c.Receipts)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Timestamp.Before(out[j].Timestamp)
	})
	return out
}
