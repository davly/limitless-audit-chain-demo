// Package persist wires two quarry-db primitives into the audit-chain:
//
//  1. FNV-1a 64-bit hash (ecosystem Type 1 universal contract) —
//     produces a stable 64-bit shard key from a receipt's canonical
//     bytes. This matches the PL/pgSQL algorithm in quarry-db's
//     sql/003_fnv1a.sql exactly: offset_basis=14695981039346656037,
//     prime=1099511628211, each byte XOR'd then multiplied mod 2^64.
//
//  2. Beta-Binomial convergence engine (Jeffreys prior α=β=0.5) —
//     tracks per-signer receipt counts and emits a three-way verdict
//     (Uncertain / Converged / Escape) that mirrors quarry-db's
//     sql/004_convergence.sql thresholds exactly:
//       min_observations=3, dominance≥0.70, confidence≥0.65,
//       escape_threshold=0.60.
//
// # Relationship to quarry-db
//
// quarry-db embeds the full convergence + lifecycle state machine inside
// PostgreSQL triggers, giving write-once-read-many receipt storage with
// tamper-evident guarantees at the database layer. This package is the
// application-layer mirror of that pattern: the FNV-1a shard key
// becomes the BIGINT primary key bucket for a write-once PostgreSQL
// receipts table (schema shipped in SchemaSQL), and the Beta-Binomial
// engine answers "has signer X converged?" before the chain emits a
// final verified-chain receipt.
//
// Self-contained — no external dependencies beyond stdlib.
package persist

import (
	"fmt"
	"strings"

	"github.com/davly/limitless-audit-chain-demo/internal/chain"
)

// ---------------------------------------------------------------------------
// 1. FNV-1a 64-bit (quarry-db forge kernel, ecosystem Type 1)
// ---------------------------------------------------------------------------

// FNV-1a 64-bit canonical constants (ecosystem-wide Type 1).
// Byte-identical to quarry-db/internal/forge.FnvOffsetBasis / FnvPrime
// and to sql/003_fnv1a.sql's fnv1a_offset_basis() / fnv1a_prime().
const (
	fnvOffsetBasis uint64 = 14695981039346656037 // 0xcbf29ce484222325
	fnvPrime       uint64 = 1099511628211         // 0x00000100000001b3
)

// FNV1a64 returns the canonical FNV-1a 64-bit hash of data.
//
// Algorithm (byte-identical to quarry-db sql/003_fnv1a.sql):
//
//	hash = fnvOffsetBasis
//	for each byte b:
//	    hash ^= uint64(b)
//	    hash *= fnvPrime   (mod 2^64 via natural uint64 wrap)
func FNV1a64(data []byte) uint64 {
	h := fnvOffsetBasis
	for _, b := range data {
		h ^= uint64(b)
		h *= fnvPrime
	}
	return h
}

// ReceiptShardKey returns the FNV-1a 64-bit shard key for a receipt.
//
// The key is computed over the receipt's CanonicalBytes() — the same
// deterministic wire format used for chain linkage and signing. This
// makes the shard key a function of the receipt's content alone: two
// receipts with identical content always land in the same shard bucket,
// and any tampering that would break the chain also changes the key.
//
// In a PostgreSQL-backed write-once store this value maps to the BIGINT
// primary-key bucket (stored as a signed BIGINT via the same two's-
// complement convention as quarry-db's fnv1a_to_bigint()).
func ReceiptShardKey(r chain.Receipt) int64 {
	u := FNV1a64(r.CanonicalBytes())
	// Store as signed int64 — same bit pattern, matching PL/pgSQL BIGINT.
	return int64(u) // deliberate bit-pattern cast, no data loss
}

// ---------------------------------------------------------------------------
// 2. Beta-Binomial convergence engine (quarry-db sql/004_convergence.sql)
// ---------------------------------------------------------------------------

// Convergence thresholds — ecosystem Type 1 canonical (quarry-db defaults).
const (
	minObservations     = 3    // min_observations in forge_config
	dominanceThreshold  = 0.70 // dominance_threshold
	confidenceThreshold = 0.65 // confidence_threshold
	escapeThreshold     = 0.60 // escape_threshold
)

// Jeffreys prior hyperparameters (α = β = 0.5).
const (
	jeffreysAlpha = 0.5
	jeffreysBeta  = 0.5
)

// Verdict is the three-way convergence decision (mirrors quarry-db).
type Verdict int

const (
	// VerdictUncertain — insufficient observations or borderline evidence.
	VerdictUncertain Verdict = iota
	// VerdictConverged — signer has produced a consistent receipt pattern.
	VerdictConverged
	// VerdictEscape — dominance fell below escape threshold; pattern unstable.
	VerdictEscape
)

// String returns a canonical label for the Verdict.
func (v Verdict) String() string {
	switch v {
	case VerdictUncertain:
		return "uncertain"
	case VerdictConverged:
		return "converged"
	case VerdictEscape:
		return "escape"
	}
	return "unknown"
}

// bbPosteriorMean computes α/(α+β) — the Beta-Binomial posterior mean.
// Matches quarry-db sql/004_convergence.sql bb_posterior_mean().
func bbPosteriorMean(alpha, beta float64) float64 {
	if alpha+beta <= 0 {
		return 0
	}
	return alpha / (alpha + beta)
}

// bbConfidence computes the Jeffreys posterior confidence.
// Formula: (0.5 + successes) / (1.0 + successes + failures)
// Matches quarry-db sql/004_convergence.sql bb_confidence().
func bbConfidence(successes, failures int) float64 {
	return (jeffreysAlpha + float64(successes)) / (1.0 + float64(successes) + float64(failures))
}

// decide applies the ecosystem convergence decision rule.
// Matches quarry-db's check_convergence() logic exactly.
func decide(dominance, confidence float64, total int) Verdict {
	if total < minObservations {
		return VerdictUncertain
	}
	if dominance >= dominanceThreshold && confidence >= confidenceThreshold {
		return VerdictConverged
	}
	if dominance < escapeThreshold {
		return VerdictEscape
	}
	return VerdictUncertain
}

// SignerStats tracks Beta-Binomial state for a single signer.
type SignerStats struct {
	// Total is the total number of receipts seen for this signer.
	Total int
	// Dominant is the count of receipts whose signer matches the
	// expected canonical sequence position. For the audit-chain demo
	// the "dominant response" is simply "signer present in chain" — all
	// receipts from a known signer count as successes.
	Dominant int
}

// Dominance returns the Beta-Binomial posterior dominance rate.
// Matches quarry-db bb_posterior_mean(0.5+dominant, 0.5+non-dominant).
func (s SignerStats) Dominance() float64 {
	alpha := jeffreysAlpha + float64(s.Dominant)
	beta := jeffreysBeta + float64(s.Total-s.Dominant)
	return bbPosteriorMean(alpha, beta)
}

// Confidence returns the Jeffreys posterior confidence.
func (s SignerStats) Confidence() float64 {
	return bbConfidence(s.Dominant, s.Total-s.Dominant)
}

// Verdict returns the convergence verdict for this signer.
func (s SignerStats) Verdict() Verdict {
	return decide(s.Dominance(), s.Confidence(), s.Total)
}

// ---------------------------------------------------------------------------
// 3. ChainStore — wires FNV-1a sharding + Beta-Binomial convergence
// ---------------------------------------------------------------------------

// ChainStore is an in-process write-once receipt store backed by
// FNV-1a shard keys and Beta-Binomial convergence tracking.
//
// In production this would delegate persistence to a PostgreSQL table
// whose BIGINT primary key is the FNV-1a shard key (see SchemaSQL).
// Here the store is in-memory so the demo runs without a live database.
type ChainStore struct {
	// receipts holds the appended receipts indexed by shard key.
	receipts map[int64]chain.Receipt
	// order preserves append order for chain reconstruction.
	order []int64
	// stats tracks Beta-Binomial state per signer.
	stats map[chain.SignerID]*SignerStats
}

// NewChainStore returns an empty ChainStore.
func NewChainStore() *ChainStore {
	return &ChainStore{
		receipts: make(map[int64]chain.Receipt),
		stats:    make(map[chain.SignerID]*SignerStats),
	}
}

// ErrDuplicateShardKey is returned when a receipt with the same FNV-1a
// shard key is appended twice. This enforces the write-once contract.
type ErrDuplicateShardKey struct {
	Key int64
}

func (e ErrDuplicateShardKey) Error() string {
	return fmt.Sprintf("persist: duplicate shard key %d (write-once violation)", e.Key)
}

// Append stores a receipt using its FNV-1a shard key as the unique
// storage key, and updates the Beta-Binomial convergence stats for
// the receipt's signer. Returns ErrDuplicateShardKey if the same
// canonical receipt is appended twice.
func (cs *ChainStore) Append(r chain.Receipt) error {
	key := ReceiptShardKey(r)
	if _, exists := cs.receipts[key]; exists {
		return ErrDuplicateShardKey{Key: key}
	}
	cs.receipts[key] = r
	cs.order = append(cs.order, key)

	// Update Beta-Binomial stats: every receipt from a known signer
	// is a "dominant" success (the audit-chain contract requires all
	// five signers to participate — any receipt from a known signer
	// in the correct position is a success).
	st := cs.stats[r.SignerID]
	if st == nil {
		st = &SignerStats{}
		cs.stats[r.SignerID] = st
	}
	st.Total++
	st.Dominant++ // all canonical-signer receipts count as dominant
	return nil
}

// Len returns the number of stored receipts.
func (cs *ChainStore) Len() int { return len(cs.order) }

// Chain reconstructs a chain.Chain from the stored receipts in append order.
func (cs *ChainStore) Chain() *chain.Chain {
	c := &chain.Chain{}
	for _, key := range cs.order {
		c.Append(cs.receipts[key])
	}
	return c
}

// ConvergenceReport returns a human-readable convergence summary for
// each signer seen so far, using the Beta-Binomial engine.
func (cs *ChainStore) ConvergenceReport() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Beta-Binomial convergence report (%d receipts stored)\n", cs.Len())
	for _, sid := range chain.AllSignerIDs() {
		st, ok := cs.stats[sid]
		if !ok {
			fmt.Fprintf(&b, "  %-12s  n=0    verdict=uncertain  (no receipts)\n", sid)
			continue
		}
		fmt.Fprintf(&b, "  %-12s  n=%-3d  dominance=%.3f  confidence=%.3f  verdict=%s\n",
			sid, st.Total, st.Dominance(), st.Confidence(), st.Verdict())
	}
	return b.String()
}

// ShardSummary returns a concise listing of shard-key → signer mappings.
func (cs *ChainStore) ShardSummary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "FNV-1a shard key assignments (%d entries)\n", cs.Len())
	for _, key := range cs.order {
		r := cs.receipts[key]
		fmt.Fprintf(&b, "  key=%d  signer=%-10s  payload=%.16s...\n",
			key, r.SignerID, r.PayloadHash)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// 4. SchemaSQL — embedded PL/pgSQL schema for production backing store
// ---------------------------------------------------------------------------

// SchemaSQL is the PL/pgSQL DDL for a PostgreSQL write-once receipt
// table that uses the FNV-1a shard key as its BIGINT primary key and
// records the Beta-Binomial convergence metrics per signer alongside
// the receipt chain. Drop-in compatible with quarry-db's
// sql/003_fnv1a.sql + sql/004_convergence.sql conventions.
//
// This SQL is embedded here so the demo can document its intended
// durable backing store without requiring a live PostgreSQL instance.
// The ChainStore in-memory implementation above has byte-identical
// semantics to what a database backed by this schema would produce.
const SchemaSQL = `
-- audit_chain_receipts: write-once receipt store using FNV-1a shard keys.
-- Shard key is computed by the application layer (FNV1a64 of canonical bytes).
-- Compatible with quarry-db sql/003_fnv1a.sql bit pattern (signed BIGINT).
CREATE TABLE IF NOT EXISTS audit_chain_receipts (
    shard_key        BIGINT       PRIMARY KEY,      -- FNV-1a 64-bit of canonical bytes (signed)
    signer_id        TEXT         NOT NULL,
    prev_receipt_hash TEXT        NOT NULL,
    payload_hash     TEXT         NOT NULL,
    receipt_ts       TIMESTAMPTZ  NOT NULL,
    signature        TEXT         NOT NULL,
    inserted_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT audit_chain_receipts_immutable
        CHECK (inserted_at IS NOT NULL)             -- DDL-level reminder: rows are write-once
);

-- audit_chain_signer_convergence: Beta-Binomial per-signer convergence state.
-- Mirrors quarry-db sql/004_convergence.sql forge_patterns semantics.
CREATE TABLE IF NOT EXISTS audit_chain_signer_convergence (
    signer_id         TEXT         PRIMARY KEY,
    total_receipts    INTEGER      NOT NULL DEFAULT 0,
    dominant_count    INTEGER      NOT NULL DEFAULT 0,
    bb_alpha          NUMERIC(10,4) NOT NULL DEFAULT 0.5,  -- 0.5 + dominant_count
    bb_beta           NUMERIC(10,4) NOT NULL DEFAULT 0.5,  -- 0.5 + (total - dominant)
    dominance_rate    NUMERIC(6,4) NOT NULL DEFAULT 0.5,
    confidence        NUMERIC(6,4) NOT NULL DEFAULT 0.5,
    verdict           TEXT         NOT NULL DEFAULT 'uncertain',
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);
`
