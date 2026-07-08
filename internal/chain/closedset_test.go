package chain

import (
	"errors"
	"testing"
	"time"
)

// closedset_test.go guards the one behaviour that WOULD have flipped under
// a naive repoint: the SDK's Verify is open-by-default (any non-empty
// signer accepted), whereas the demo rejects any signer outside its closed
// five-set. The shim's Chain.Verify pins RequireSigners to AllSignerIDs()
// to preserve the demo semantics; these tests prove the pin holds.

// TestClosedSet_UnknownSignerStillRejectedViaShim proves a chain whose
// receipt carries a signer outside the five-set is rejected with
// ErrUnknownSigner — despite the SDK's open-by-default Verify.
func TestClosedSet_UnknownSignerStillRejectedViaShim(t *testing.T) {
	c := &Chain{}
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     phash("x"),
		SignerID:        SignerID("rogue"),
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Signature:       "sig",
	})
	if err := c.Verify(func(Receipt) error { return nil }); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("rogue signer: got %v, want ErrUnknownSigner", err)
	}
}

// TestClosedSet_FiveCanonicalSignersAccepted confirms the canonical
// five-step pipeline still verifies through the shim.
func TestClosedSet_FiveCanonicalSignersAccepted(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	c := &Chain{}

	prev := GenesisPrevHash
	signers := AllSignerIDs()
	for i, s := range signers {
		r := Receipt{
			PrevReceiptHash: prev,
			PayloadHash:     phash(string(s) + "-payload"),
			SignerID:        s,
			Timestamp:       t0.Add(time.Duration(i) * time.Second),
			Signature:       "sig",
		}
		c.Append(r)
		prev = r.Hash()
	}

	if err := c.Verify(func(Receipt) error { return nil }); err != nil {
		t.Fatalf("five canonical signers: unexpected Verify error: %v", err)
	}
	if c.Len() != 5 {
		t.Fatalf("Len: got %d, want 5", c.Len())
	}
}

// TestClosedSet_RealVerifierRejectsBadSignature is the SECURITY regression
// (SECURITY_NOTES iter11 #2): the repoint must use a REAL verifier, not the
// SDK's structural-only nil path. This proves that when a real VerifierFunc
// rejects a receipt's signature, Verify surfaces ErrSignatureMismatch
// rather than silently passing.
func TestClosedSet_RealVerifierRejectsBadSignature(t *testing.T) {
	c := &Chain{}
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     phash("x"),
		SignerID:        SignerDelve,
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Signature:       "tampered",
	})
	rejecting := func(Receipt) error { return errors.New("bad signature") }
	if err := c.Verify(rejecting); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("real verifier rejecting bad sig: got %v, want ErrSignatureMismatch", err)
	}
}
