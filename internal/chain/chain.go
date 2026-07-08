// Package chain is the demo's composition library for turning N
// independent signed receipts into a single tamper-evident audit chain
// — the load-bearing primitive behind R-CROSS-INFRA-AUDIT-CHAIN-EMIT.
//
// # Repoint to the canonical SDK (cross-poll graft)
//
// This package was originally an in-tree FORK of the audit-chain
// primitive. It is now a thin RE-EXPORT SHIM over the cohort-canonical
// SDK extraction #8:
//
//	github.com/davly/limitless-audit-chain/pkg/chain
//
// All of the load-bearing logic — CanonicalBytes / Hash / Verify /
// IsGenesis / Receipt / Chain / the error sentinels — now lives in the
// SDK and is consumed read-only. The demo no longer carries a forked
// copy that can drift from the canonical wire format.
//
// # Why a shim and not a bare s/internal\/chain/sdk/ repoint
//
// The SDK deliberately makes SignerID an OPEN string type (any caller-
// defined signer is accepted at the chain layer; closed-set enforcement
// is opt-in via Chain.RequireSigners). The I20 demo, by contrast,
// hard-codes a CLOSED set of five signers (delve / grounded / recall /
// echo / parallax) and rejects anything else. Two demo-specific
// behaviours therefore do NOT exist in the open SDK and are preserved
// here:
//
//  1. The five signer constants + AllSignerIDs / IsKnownSignerID, which
//     internal/emitters and the test suite reference directly.
//  2. The closed-set rejection semantics: a chain whose receipt carries
//     a signer outside the five-set must fail Verify with
//     ErrUnknownSigner. The shim's Chain.Verify pins the embedded SDK
//     chain's RequireSigners to the five-set so the SDK's open-by-
//     default Verify enforces the demo's closed set.
//
// The shim keeps the package's exported surface byte-for-byte identical
// (same type names, constants, funcs, error vars), so internal/emitters,
// cmd/, and every existing test compile and behave UNCHANGED — only the
// implementation underneath is now the SDK.
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
// callers who legitimately hold a variable-length chain. VerifyToTip
// and VerifyN are demo-local additions layered on top of the shim —
// the open SDK does not (yet) carry a tail-truncation guard.
//
// # Honest scope (unchanged from the fork)
//
// This package implements the chain composition primitive only — it does
// NOT itself verify upstream signatures. Each receipt carries a signer-id
// and a payload-hash; the chain layer enforces the prev-receipt-hash
// linkage + temporal ordering and dispatches each receipt's signature to
// a caller-supplied VerifierFunc. The demo wires a REAL Mirror-Mark
// verifier (internal/emitters.MirrorMarkVerifier); the structural-only
// nil-verifier path is NEVER used on the demo's verification surface.
package chain

import (
	"crypto/hmac"
	"errors"
	"fmt"

	sdk "github.com/davly/limitless-audit-chain/pkg/chain"
)

// ----- Canonical SDK types, re-exported so importers are unchanged -----

// SignerID identifies which upstream emitter signed the receipt. Aliased
// to the SDK's open SignerID type; the demo layers its closed five-set
// on top via the constants + Chain.Verify below.
type SignerID = sdk.SignerID

// Receipt is a single signed step in the cross-infra audit chain. Aliased
// to the canonical SDK Receipt — same wire format / CanonicalBytes / Hash.
type Receipt = sdk.Receipt

// VerifierFunc verifies the signature of a single receipt. Aliased to the
// SDK's VerifierFunc (identical signature `func(Receipt) error`).
type VerifierFunc = sdk.VerifierFunc

// GenesisPrevHash is the 64-character "no-predecessor" sentinel. Sourced
// from the SDK so the genesis constant cannot drift between the two.
const GenesisPrevHash = sdk.GenesisPrevHash

// ----- Demo-specific closed-set signer cohort (NOT in the open SDK) -----

// The five canonical signer IDs match the five I20 pipeline steps. The
// SDK has no such constants (its SignerID is an open string type), so the
// demo declares them locally and enforces the closed set in Chain.Verify.
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

// ----- Error sentinels, re-exported as errors.Is targets -----
//
// Aliased to the SDK sentinels so callers' errors.Is(err, chain.ErrX)
// continues to match the errors the SDK's Verify returns.
var (
	ErrEmptyChain        = sdk.ErrEmptyChain
	ErrGenesisPrevHash   = sdk.ErrGenesisPrevHash
	ErrUnknownSigner     = sdk.ErrUnknownSigner
	ErrPrevHashMismatch  = sdk.ErrPrevHashMismatch
	ErrTimestampInverted = sdk.ErrTimestampInverted
	ErrEmptySignature    = sdk.ErrEmptySignature
	ErrSignatureMismatch = sdk.ErrSignatureMismatch
)

// ----- Chain: thin wrapper pinning the demo's closed signer set -----

// Chain wraps the SDK chain. It exists only to pin RequireSigners to the
// demo's closed five-set during Verify, so the demo's "unknown signer
// rejected" semantics (chain_test.go TestVerify_UnknownSignerRejected)
// are preserved against the SDK's open-by-default Verify. Every other
// method delegates straight to the embedded SDK chain.
//
// The zero value is a valid empty chain (the embedded sdk.Chain's zero
// value is valid), so `&chain.Chain{}` literal construction — used in
// main.go and the test suite — continues to work unchanged. Field access
// to c.Receipts resolves through the embedded sdk.Chain.
type Chain struct {
	sdk.Chain
}

// Append adds a receipt to the chain. The caller is responsible for
// setting the receipt's PrevReceiptHash correctly — the chain layer does
// NOT compute it automatically.
func (c *Chain) Append(r Receipt) { c.Chain.Append(r) }

// Len returns the chain length.
func (c *Chain) Len() int { return c.Chain.Len() }

// SignerSequence returns the signer IDs in append order.
func (c *Chain) SignerSequence() []SignerID { return c.Chain.SignerSequence() }

// SortedReceiptsCopy returns a defensive copy of the chain's receipts
// sorted by Timestamp ascending.
func (c *Chain) SortedReceiptsCopy() []Receipt { return c.Chain.SortedReceiptsCopy() }

// ErrTipMismatch — the chain's last receipt Hash() does not equal the
// expected tip supplied to VerifyToTip. This is the truncation /
// receipt-removal guard: a structurally-valid chain whose trailing
// receipts have been dropped passes plain Verify (genesis intact,
// every prev-hash links, every signature verifies) but FAILS
// VerifyToTip when the verifier was told the chain must end at a
// specific receipt hash. Demo-local sentinel — the open SDK does not
// (yet) carry a tail-truncation guard.
var ErrTipMismatch = errors.New("chain: chain tip does not match expected tip (possible tail-truncation / receipt-removal)")

// ErrLengthMismatch — the chain's length does not equal the expected
// length supplied to VerifyN. The length-pinned sibling of
// ErrTipMismatch for callers who were handed an expected receipt
// count rather than a tip hash. Demo-local sentinel.
var ErrLengthMismatch = errors.New("chain: chain length does not match expected length (possible tail-truncation / receipt-removal)")

// Verify enforces the demo's closed signer set, then delegates to the
// SDK's Verify. It pins RequireSigners to AllSignerIDs() (idempotently)
// so a signer outside the five-set is rejected with ErrUnknownSigner —
// the demo's closed-set semantics — even though the SDK's Verify accepts
// any non-empty signer by default.
//
// SECURITY: callers MUST pass a real VerifierFunc (e.g.
// internal/emitters.MirrorMarkVerifier). A nil verifier would make the
// SDK skip per-receipt signature checks (structural-only) and hollow out
// the tamper-evidence claim; the demo's verification surface never does
// this.
func (c *Chain) Verify(v VerifierFunc) error {
	if c.Chain.RequireSigners == nil {
		c.Chain.RequireSigners = AllSignerIDs()
	}
	return c.Chain.Verify(v)
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
