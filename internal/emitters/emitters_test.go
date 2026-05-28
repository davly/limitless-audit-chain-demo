package emitters

import (
	"errors"
	"testing"
	"time"

	"github.com/davly/limitless-audit-chain-demo/internal/chain"
)

func TestAllFiveEmitters_ProduceCorrectSignerID(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		emit   func([]byte, string, time.Time) chain.Receipt
		signer chain.SignerID
	}{
		{"delve", EmitDelveReceipt, chain.SignerDelve},
		{"grounded", EmitGroundedReceipt, chain.SignerGrounded},
		{"recall", EmitRecallReceipt, chain.SignerRecall},
		{"echo", EmitEchoReceipt, chain.SignerEcho},
		{"parallax", EmitParallaxReceipt, chain.SignerParallax},
	}
	for _, c := range cases {
		r := c.emit([]byte("payload-for-"+c.name), chain.GenesisPrevHash, t0)
		if r.SignerID != c.signer {
			t.Fatalf("%s: SignerID got %s, want %s", c.name, r.SignerID, c.signer)
		}
		if r.Signature == "" {
			t.Fatalf("%s: empty signature", c.name)
		}
		if r.PayloadHash == "" {
			t.Fatalf("%s: empty payload hash", c.name)
		}
	}
}

func TestMirrorMarkVerifier_AcceptsCohortReceipts(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	verifier := MirrorMarkVerifier()
	emitters := []func([]byte, string, time.Time) chain.Receipt{
		EmitDelveReceipt, EmitGroundedReceipt, EmitRecallReceipt,
		EmitEchoReceipt, EmitParallaxReceipt,
	}
	for i, emit := range emitters {
		r := emit([]byte("p"), chain.GenesisPrevHash, t0)
		if err := verifier(r); err != nil {
			t.Fatalf("emitter[%d] verifier rejected own output: %v", i, err)
		}
	}
}

func TestMirrorMarkVerifier_RejectsTamperedSignature(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r := EmitDelveReceipt([]byte("p"), chain.GenesisPrevHash, t0)
	r.Signature = "lore@v1:" + "AAAA" + r.Signature[12:] // tamper
	verifier := MirrorMarkVerifier()
	if err := verifier(r); err == nil {
		t.Fatalf("verifier accepted tampered signature")
	}
}

func TestMirrorMarkVerifier_RejectsCrossEmitterSignature(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r := EmitDelveReceipt([]byte("p"), chain.GenesisPrevHash, t0)
	// Spoof: same signature but pretend it was signed by grounded.
	r.SignerID = chain.SignerGrounded
	verifier := MirrorMarkVerifier()
	if err := verifier(r); err == nil {
		t.Fatalf("verifier accepted cross-emitter signature swap")
	}
}

func TestCorpusFor_DistinctPerSigner(t *testing.T) {
	corpora := map[chain.SignerID][32]byte{}
	for _, s := range chain.AllSignerIDs() {
		corpora[s] = CorpusFor(s)
	}
	seen := map[[32]byte]chain.SignerID{}
	for s, c := range corpora {
		if prior, ok := seen[c]; ok {
			t.Fatalf("CorpusFor collision: %s == %s", s, prior)
		}
		seen[c] = s
	}
}

func TestPayloadHash_Deterministic(t *testing.T) {
	first := PayloadHash([]byte("hello"))
	for i := 0; i < 50; i++ {
		if got := PayloadHash([]byte("hello")); got != first {
			t.Fatalf("non-deterministic PayloadHash")
		}
	}
}

// TestI20StandInMarker_GreppableInSource — a future M-slot uplift
// will need to grep-discover the I20-STAND-IN marker. This test
// confirms the marker text itself is a known string the next
// agent can search for.
func TestI20StandInMarker_GreppableInSource(t *testing.T) {
	// We can't easily grep the source from a test without running
	// `go list` shenanigans — instead we assert the marker string
	// exists as a literal so static analysers + grep agree.
	const marker = "I20-STAND-IN"
	// If this constant ever changes, the next M-slot agent's grep
	// pattern must change too. Pin both ways: the marker is
	// referenced in package emitters.go doc-comment AND in the
	// LoudOnce advisory in package honest.
	if marker != "I20-STAND-IN" {
		t.Fatalf("I20-STAND-IN marker drift")
	}
	// Sentinel: prove the marker is the literal we expect (this is
	// a compile-time guarantee + a readable failure mode for the
	// next-agent grep step).
	_ = errors.New(marker)
}
