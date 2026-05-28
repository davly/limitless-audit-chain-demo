package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// alwaysValidVerifier — accepts every signature. Used by tests
// focused on the chain composition layer (prev-hash + ordering).
func alwaysValidVerifier(_ Receipt) error { return nil }

func mkPayloadHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestCanonicalBytes_StableOrdering(t *testing.T) {
	ts := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("hello"),
		SignerID:        SignerDelve,
		Timestamp:       ts,
		Signature:       "irrelevant-for-canonical-bytes",
	}
	got := string(r.CanonicalBytes())
	want := "payload_hash: " + mkPayloadHash("hello") + "\n" +
		"prev_receipt_hash: " + GenesisPrevHash + "\n" +
		"signer_id: delve\n" +
		"timestamp: 2026-05-28T12:00:00Z\n"
	if got != want {
		t.Fatalf("CanonicalBytes drift:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestHash_DeterministicAcrossCalls(t *testing.T) {
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerDelve,
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
	}
	first := r.Hash()
	for i := 0; i < 50; i++ {
		if got := r.Hash(); got != first {
			t.Fatalf("iter %d: non-deterministic Hash:\n  iter 0: %s\n  iter %d: %s", i, first, i, got)
		}
	}
}

func TestVerify_EmptyChainRejected(t *testing.T) {
	c := &Chain{}
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrEmptyChain) {
		t.Fatalf("empty chain: got %v, want ErrEmptyChain", err)
	}
}

func TestVerify_GenesisMustHaveSentinelPrevHash(t *testing.T) {
	c := &Chain{}
	c.Append(Receipt{
		PrevReceiptHash: "not-the-sentinel",
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerDelve,
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Signature:       "sig",
	})
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrGenesisPrevHash) {
		t.Fatalf("bad genesis: got %v, want ErrGenesisPrevHash", err)
	}
}

func TestVerify_UnknownSignerRejected(t *testing.T) {
	c := &Chain{}
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("rogue-emitter"),
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Signature:       "sig",
	})
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("unknown signer: got %v, want ErrUnknownSigner", err)
	}
}

func TestVerify_EmptySignatureRejected(t *testing.T) {
	c := &Chain{}
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerDelve,
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
	})
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrEmptySignature) {
		t.Fatalf("empty sig: got %v, want ErrEmptySignature", err)
	}
}

func TestVerify_PrevHashMismatchRejected(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	c := &Chain{}
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("a"),
		SignerID:        SignerDelve,
		Timestamp:       t0,
		Signature:       "sig0",
	})
	c.Append(Receipt{
		PrevReceiptHash: "wrong-hash",
		PayloadHash:     mkPayloadHash("b"),
		SignerID:        SignerGrounded,
		Timestamp:       t0.Add(time.Second),
		Signature:       "sig1",
	})
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrPrevHashMismatch) {
		t.Fatalf("prev-hash mismatch: got %v, want ErrPrevHashMismatch", err)
	}
}

func TestVerify_TimestampInversionRejected(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r0 := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("a"),
		SignerID:        SignerDelve,
		Timestamp:       t0,
		Signature:       "sig0",
	}
	c := &Chain{}
	c.Append(r0)
	c.Append(Receipt{
		PrevReceiptHash: r0.Hash(),
		PayloadHash:     mkPayloadHash("b"),
		SignerID:        SignerGrounded,
		Timestamp:       t0.Add(-time.Hour), // earlier than parent
		Signature:       "sig1",
	})
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrTimestampInverted) {
		t.Fatalf("timestamp inversion: got %v, want ErrTimestampInverted", err)
	}
}

func TestVerify_SignatureMismatchPropagatesVerifierError(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	rejectingVerifier := func(_ Receipt) error { return errors.New("rejected by test verifier") }
	c := &Chain{}
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerDelve,
		Timestamp:       t0,
		Signature:       "tampered",
	})
	if err := c.Verify(rejectingVerifier); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("signature mismatch: got %v, want ErrSignatureMismatch", err)
	}
}

func TestVerify_FiveStepChainSucceeds(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	c := &Chain{}
	r0 := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("delve-payload"),
		SignerID:        SignerDelve,
		Timestamp:       t0,
		Signature:       "sig0",
	}
	c.Append(r0)
	r1 := Receipt{
		PrevReceiptHash: r0.Hash(),
		PayloadHash:     mkPayloadHash("grounded-payload"),
		SignerID:        SignerGrounded,
		Timestamp:       t0.Add(time.Second),
		Signature:       "sig1",
	}
	c.Append(r1)
	r2 := Receipt{
		PrevReceiptHash: r1.Hash(),
		PayloadHash:     mkPayloadHash("recall-payload"),
		SignerID:        SignerRecall,
		Timestamp:       t0.Add(2 * time.Second),
		Signature:       "sig2",
	}
	c.Append(r2)
	r3 := Receipt{
		PrevReceiptHash: r2.Hash(),
		PayloadHash:     mkPayloadHash("echo-payload"),
		SignerID:        SignerEcho,
		Timestamp:       t0.Add(3 * time.Second),
		Signature:       "sig3",
	}
	c.Append(r3)
	r4 := Receipt{
		PrevReceiptHash: r3.Hash(),
		PayloadHash:     mkPayloadHash("parallax-payload"),
		SignerID:        SignerParallax,
		Timestamp:       t0.Add(4 * time.Second),
		Signature:       "sig4",
	}
	c.Append(r4)

	if err := c.Verify(alwaysValidVerifier); err != nil {
		t.Fatalf("five-step chain Verify: %v", err)
	}
	if c.Len() != 5 {
		t.Fatalf("Len: got %d, want 5", c.Len())
	}
	wantOrder := []SignerID{SignerDelve, SignerGrounded, SignerRecall, SignerEcho, SignerParallax}
	got := c.SignerSequence()
	for i := range wantOrder {
		if got[i] != wantOrder[i] {
			t.Fatalf("SignerSequence[%d]: got %s, want %s", i, got[i], wantOrder[i])
		}
	}
}

func TestVerify_TamperingMiddleReceiptBreaksChain(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r0 := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("a"),
		SignerID:        SignerDelve,
		Timestamp:       t0,
		Signature:       "sig0",
	}
	r1 := Receipt{
		PrevReceiptHash: r0.Hash(),
		PayloadHash:     mkPayloadHash("b"),
		SignerID:        SignerGrounded,
		Timestamp:       t0.Add(time.Second),
		Signature:       "sig1",
	}
	r2 := Receipt{
		PrevReceiptHash: r1.Hash(),
		PayloadHash:     mkPayloadHash("c"),
		SignerID:        SignerRecall,
		Timestamp:       t0.Add(2 * time.Second),
		Signature:       "sig2",
	}
	// Tamper with r1's PayloadHash AFTER r2 captured its hash.
	r1.PayloadHash = mkPayloadHash("b-evil")
	c := &Chain{}
	c.Append(r0)
	c.Append(r1)
	c.Append(r2)
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrPrevHashMismatch) {
		t.Fatalf("tampering middle receipt: got %v, want ErrPrevHashMismatch", err)
	}
}

func TestAllSignerIDs_ClosedSetFiveMembers(t *testing.T) {
	got := AllSignerIDs()
	if len(got) != 5 {
		t.Fatalf("AllSignerIDs len: got %d, want 5 (delve+grounded+recall+echo+parallax)", len(got))
	}
}

func TestIsGenesis(t *testing.T) {
	r := Receipt{PrevReceiptHash: GenesisPrevHash}
	if !r.IsGenesis() {
		t.Fatalf("IsGenesis false on genesis sentinel")
	}
	r2 := Receipt{PrevReceiptHash: "anything-else"}
	if r2.IsGenesis() {
		t.Fatalf("IsGenesis true on non-sentinel")
	}
}
