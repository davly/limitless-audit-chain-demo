package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	sdk "github.com/davly/limitless-audit-chain/pkg/chain"
)

// parity_test.go is the KAT-pin (R145 paired regression) asserting that
// the repoint to the canonical SDK preserves byte-parity on the load-
// bearing wire format. If the SDK ever drifts from the demo's frozen
// expectation, these tests trip LOUDLY.

func phash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestParity_CanonicalBytesMatchesFrozenGolden pins the exact canonical
// byte string AND proves the shim's Receipt (the SDK Receipt) and a
// freshly-constructed sdk.Receipt emit byte-identical canonical bytes.
func TestParity_CanonicalBytesMatchesFrozenGolden(t *testing.T) {
	ts := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     phash("hello"),
		SignerID:        SignerDelve,
		Timestamp:       ts,
		Signature:       "irrelevant-for-canonical-bytes",
	}

	// Frozen golden — identical to the string pinned in
	// chain_test.go::TestCanonicalBytes_StableOrdering, captured before
	// the repoint.
	want := "payload_hash: " + phash("hello") + "\n" +
		"prev_receipt_hash: " + GenesisPrevHash + "\n" +
		"signer_id: delve\n" +
		"timestamp: 2026-05-28T12:00:00Z\n"

	if got := string(r.CanonicalBytes()); got != want {
		t.Fatalf("shim CanonicalBytes drift:\n  got:  %q\n  want: %q", got, want)
	}

	// Byte-for-byte parity against a directly-constructed SDK Receipt.
	sr := sdk.Receipt{
		PrevReceiptHash: sdk.GenesisPrevHash,
		PayloadHash:     phash("hello"),
		SignerID:        sdk.SignerID("delve"),
		Timestamp:       ts,
		Signature:       "irrelevant-for-canonical-bytes",
	}
	if got := string(sr.CanonicalBytes()); got != want {
		t.Fatalf("SDK CanonicalBytes drift vs frozen golden:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestParity_HashMatchesFrozenHex pins Receipt.Hash() to the literal hex
// captured from a green run before the repoint. Any canonical-bytes drift
// in the SDK trips this test.
func TestParity_HashMatchesFrozenHex(t *testing.T) {
	ts := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     phash("hello"),
		SignerID:        SignerDelve,
		Timestamp:       ts,
	}
	const frozenHex = "743c71748cd19c823588938d4edf76e15db55cc5fcd27c799e716b05f0944a80"
	if got := r.Hash(); got != frozenHex {
		t.Fatalf("Hash drift:\n  got:  %s\n  want: %s", got, frozenHex)
	}
}

// TestParity_GenesisPrevHashConstantUnchanged confirms the genesis
// sentinel is still "0"x64 after sourcing it from the SDK.
func TestParity_GenesisPrevHashConstantUnchanged(t *testing.T) {
	want := strings.Repeat("0", 64)
	if GenesisPrevHash != want {
		t.Fatalf("GenesisPrevHash drift:\n  got:  %q\n  want: %q", GenesisPrevHash, want)
	}
	if GenesisPrevHash != sdk.GenesisPrevHash {
		t.Fatalf("shim GenesisPrevHash != SDK GenesisPrevHash")
	}
}
