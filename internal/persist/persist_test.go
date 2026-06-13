package persist

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/davly/limitless-audit-chain-demo/internal/chain"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mkPayloadHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var t0 = time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

func makeReceipt(signer chain.SignerID, payload, prevHash string, ts time.Time) chain.Receipt {
	return chain.Receipt{
		PrevReceiptHash: prevHash,
		PayloadHash:     mkPayloadHash(payload),
		SignerID:        signer,
		Timestamp:       ts,
		Signature:       "test-sig",
	}
}

// ---------------------------------------------------------------------------
// FNV-1a 64-bit tests
// ---------------------------------------------------------------------------

// TestFNV1a64_EmptyInput validates the known FNV-1a offset-basis for empty input.
// FNV1a64([]byte{}) must equal the offset basis 14695981039346656037.
func TestFNV1a64_EmptyInput(t *testing.T) {
	got := FNV1a64([]byte{})
	want := uint64(fnvOffsetBasis) // empty input returns offset basis
	if got != want {
		t.Fatalf("FNV1a64(empty): got %d, want %d", got, want)
	}
}

// TestFNV1a64_KnownVector validates a known FNV-1a 64-bit test vector.
// FNV1a64("a"): offset_basis ^ 0x61 (97), then * prime mod 2^64.
//   = 0xaf63dc4c8601ec8c = 12638187200555641996
func TestFNV1a64_KnownVector(t *testing.T) {
	got := FNV1a64([]byte("a"))
	// FNV-1a 64-bit of "a":
	//   hash  = 14695981039346656037 (0xcbf29ce484222325)
	//   hash ^= 97 (0x61)
	//   hash *= 1099511628211 (0x00000100000001b3)  mod 2^64
	// = 12638187200555641996 (0xaf63dc4c8601ec8c)
	const want uint64 = 12638187200555641996
	if got != want {
		t.Fatalf("FNV1a64(%q): got %d (0x%016x), want %d (0x%016x)", "a", got, got, want, want)
	}
}

// TestFNV1a64_Deterministic checks FNV-1a output is deterministic across calls.
func TestFNV1a64_Deterministic(t *testing.T) {
	data := []byte("limitless-audit-chain-demo/canonical-test-vector")
	first := FNV1a64(data)
	for i := 0; i < 100; i++ {
		if got := FNV1a64(data); got != first {
			t.Fatalf("iter %d: FNV1a64 non-deterministic: got %d, want %d", i, got, first)
		}
	}
}

// TestReceiptShardKey_DeterministicAcrossReceipts verifies the shard key
// is derived from canonical bytes (same content = same key).
func TestReceiptShardKey_DeterministicAcrossReceipts(t *testing.T) {
	r := makeReceipt(chain.SignerDelve, "payload-a", chain.GenesisPrevHash, t0)
	k1 := ReceiptShardKey(r)
	k2 := ReceiptShardKey(r)
	if k1 != k2 {
		t.Fatalf("ReceiptShardKey non-deterministic: %d vs %d", k1, k2)
	}
}

// TestReceiptShardKey_DifferentPayloadsGiveDifferentKeys checks that two
// receipts with different payloads produce distinct shard keys.
func TestReceiptShardKey_DifferentPayloadsGiveDifferentKeys(t *testing.T) {
	r1 := makeReceipt(chain.SignerDelve, "payload-a", chain.GenesisPrevHash, t0)
	r2 := makeReceipt(chain.SignerDelve, "payload-b", chain.GenesisPrevHash, t0)
	k1 := ReceiptShardKey(r1)
	k2 := ReceiptShardKey(r2)
	if k1 == k2 {
		t.Fatalf("ReceiptShardKey collision for different payloads: both %d", k1)
	}
}

// ---------------------------------------------------------------------------
// Beta-Binomial convergence tests
// ---------------------------------------------------------------------------

// TestBBConfidence_JeffreysPrior validates bbConfidence matches the
// quarry-db sql/004_convergence.sql formula exactly.
func TestBBConfidence_JeffreysPrior(t *testing.T) {
	// (0.5 + 3) / (1.0 + 3 + 0) = 3.5/4.0 = 0.875
	got := bbConfidence(3, 0)
	want := 3.5 / 4.0
	if abs(got-want) > 1e-9 {
		t.Fatalf("bbConfidence(3,0): got %.9f, want %.9f", got, want)
	}
}

// TestSignerStats_ConvergedAfterThreeSuccesses verifies the canonical
// convergence thresholds fire correctly: 3 dominant receipts out of 3
// total should yield VerdictConverged.
func TestSignerStats_ConvergedAfterThreeSuccesses(t *testing.T) {
	st := &SignerStats{Total: 3, Dominant: 3}
	// dominance = (0.5+3)/(0.5+3+0.5+0) = 3.5/4.0 = 0.875 >= 0.70 ✓
	// confidence = (0.5+3)/(1.0+3+0) = 3.5/4.0 = 0.875 >= 0.65 ✓
	if v := st.Verdict(); v != VerdictConverged {
		t.Fatalf("Stats{3/3}: want VerdictConverged, got %s (dominance=%.3f confidence=%.3f)",
			v, st.Dominance(), st.Confidence())
	}
}

// TestSignerStats_UncertainBelowMinObservations validates the min-obs guard.
func TestSignerStats_UncertainBelowMinObservations(t *testing.T) {
	st := &SignerStats{Total: 2, Dominant: 2}
	if v := st.Verdict(); v != VerdictUncertain {
		t.Fatalf("Stats{2/2}: want VerdictUncertain (min_obs=3), got %s", v)
	}
}

// TestSignerStats_EscapeOnLowDominance validates the escape path:
// dominance < 0.60 → VerdictEscape regardless of confidence.
func TestSignerStats_EscapeOnLowDominance(t *testing.T) {
	// 1 dominant out of 5: dominance = (0.5+1)/(0.5+1+0.5+4) = 1.5/6.5 ≈ 0.231 < 0.60 → escape
	st := &SignerStats{Total: 5, Dominant: 1}
	if v := st.Verdict(); v != VerdictEscape {
		t.Fatalf("Stats{1/5}: want VerdictEscape, got %s (dominance=%.3f)", v, st.Dominance())
	}
}

// ---------------------------------------------------------------------------
// ChainStore integration tests
// ---------------------------------------------------------------------------

// TestChainStore_AppendAndReconstruct verifies the full 5-step chain
// survives a round-trip through the store.
func TestChainStore_AppendAndReconstruct(t *testing.T) {
	cs := NewChainStore()

	r1 := makeReceipt(chain.SignerDelve, "delve-payload", chain.GenesisPrevHash, t0)
	r2 := makeReceipt(chain.SignerGrounded, "grounded-payload", r1.Hash(), t0.Add(time.Second))
	r3 := makeReceipt(chain.SignerRecall, "recall-payload", r2.Hash(), t0.Add(2*time.Second))
	r4 := makeReceipt(chain.SignerEcho, "echo-payload", r3.Hash(), t0.Add(3*time.Second))
	r5 := makeReceipt(chain.SignerParallax, "parallax-payload", r4.Hash(), t0.Add(4*time.Second))

	for _, r := range []chain.Receipt{r1, r2, r3, r4, r5} {
		if err := cs.Append(r); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	if cs.Len() != 5 {
		t.Fatalf("Len: got %d, want 5", cs.Len())
	}

	// Reconstruct chain and verify linkage.
	c := cs.Chain()
	if c.Len() != 5 {
		t.Fatalf("Chain().Len(): got %d, want 5", c.Len())
	}
	// alwaysValidVerifier — we only test the chain-layer (prev-hash links), not signatures.
	if err := c.Verify(func(_ chain.Receipt) error { return nil }); err != nil {
		t.Fatalf("Chain().Verify: %v", err)
	}
}

// TestChainStore_WriteOnceRejectsSecondAppendOfSameReceipt verifies the
// write-once contract: appending an identical receipt twice returns an error.
func TestChainStore_WriteOnceRejectsSecondAppendOfSameReceipt(t *testing.T) {
	cs := NewChainStore()
	r := makeReceipt(chain.SignerDelve, "payload-x", chain.GenesisPrevHash, t0)
	if err := cs.Append(r); err != nil {
		t.Fatalf("first Append: %v", err)
	}
	err := cs.Append(r)
	var dup ErrDuplicateShardKey
	if !errors.As(err, &dup) {
		t.Fatalf("second Append: want ErrDuplicateShardKey, got %v", err)
	}
}

// TestChainStore_ConvergenceReportContainsAllSigners verifies the
// convergence report mentions all five canonical signers.
func TestChainStore_ConvergenceReportContainsAllSigners(t *testing.T) {
	cs := NewChainStore()
	r1 := makeReceipt(chain.SignerDelve, "delve-payload", chain.GenesisPrevHash, t0)
	r2 := makeReceipt(chain.SignerGrounded, "grounded-payload", r1.Hash(), t0.Add(time.Second))
	r3 := makeReceipt(chain.SignerRecall, "recall-payload", r2.Hash(), t0.Add(2*time.Second))
	r4 := makeReceipt(chain.SignerEcho, "echo-payload", r3.Hash(), t0.Add(3*time.Second))
	r5 := makeReceipt(chain.SignerParallax, "parallax-payload", r4.Hash(), t0.Add(4*time.Second))
	for _, r := range []chain.Receipt{r1, r2, r3, r4, r5} {
		_ = cs.Append(r)
	}
	report := cs.ConvergenceReport()
	for _, sid := range chain.AllSignerIDs() {
		if !containsString(report, string(sid)) {
			t.Errorf("ConvergenceReport missing signer %q", sid)
		}
	}
}

// TestSchemaSQL_NotEmpty sanity-checks the embedded DDL string is non-empty
// and contains the expected table names.
func TestSchemaSQL_NotEmpty(t *testing.T) {
	if len(SchemaSQL) == 0 {
		t.Fatal("SchemaSQL is empty")
	}
	for _, want := range []string{
		"audit_chain_receipts",
		"audit_chain_signer_convergence",
		"shard_key",
		"BIGINT",
	} {
		if !containsString(SchemaSQL, want) {
			t.Errorf("SchemaSQL missing expected token %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) && findSubstring(haystack, needle)
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
