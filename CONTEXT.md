# limitless-audit-chain-demo — Context

*Fresh CONTEXT.md created at I20 (2026-05-28 INFRA marathon). limitless-audit-chain-demo is a NEW flagship from inception per the cohort-port FROM INCEPTION pattern (memoria + conjure + bias-audit precedent).*

## One-line purpose

**Canonical 1st saturator of `R-CROSS-INFRA-AUDIT-CHAIN-EMIT` — a customer-grade Go showcase that composes signed receipts from five sibling infrastructure emitters (delve / grounded / recall / echo / parallax) into a single tamper-evident audit chain that an external regulator can cold-verify via OpenSSL.**

This is the **SHOWCASE artefact** that demonstrates the new R-rule `R-CROSS-INFRA-AUDIT-CHAIN-EMIT` in production code.

## Status

**Status (I20, 2026-05-28)**: **Phase-1 scaffold + showcase shipped FROM INCEPTION per R174 5-of-5 strict**. 8 internal packages (5 R174 cohort + chain + emitters + legal). All tests `go test ./... -count=1` green at launch. ReviewedByCounsel = false honest-default per R166. Mirror-Mark signature surface today; per-emitter dispatch in a follow-up M-slot once I3-I7 land.

| Field | Value |
|---|---|
| **Phase** | **Phase-1 scaffold + showcase** (Go forge kernel + chain composition library + 5 stand-in emitters + R174 5-of-5 cohort from inception + R166 founder-drafted legal cohort) |
| **Layer** | flagship — Cross-Infra Audit Chain demo (the SHOWCASE for `R-CROSS-INFRA-AUDIT-CHAIN-EMIT`) |
| **Primary language (shipped)** | **Go 1.22** (pure-Go scaffold; zero `go.mod` deps at I20 ship — every upstream SDK call is a stand-in in `internal/emitters/`) |
| **Planned surfaces (Phase 2+)** | Replace `internal/emitters/` stand-ins with real upstream SDKs once I3-I7 ship: delve / grounded / recall / echo / parallax. Introduce per-emitter signature dispatch in `internal/chain/` (today's verifier is Mirror-Mark-uniform). |
| **Active branch** | `main` |
| **Remote** | `github.com/davly/limitless-audit-chain-demo.git` |
| **Source files (Go, non-test)** | 9 (1 cmd + 8 internal) |
| **Test files (Go)** | 9 (1 end-to-end + 8 internal package _test files) |
| **Test funcs** | ~50 across all packages (chain 13 + emitters 7 + tests 5 + lore 7 + mirrormark 5 + manifest 8 + honest 8 + legal 7 + firewall 4) |
| **Internal packages** | 8 (`chain` + `emitters` + `firewall` + `honest` + `legal` + `lore` + `manifest` + `mirrormark`) |
| **R174 core (5-of-5)** | `lore` + `mirrormark` + `manifest` + `honest` + `firewall` |
| **R143 advisories** | 3 (`CROSS_INFRA_DEMO_NOT_PRODUCTION_RUNTIME` Warn + `UPSTREAM_SDK_STAND_INS_IN_USE` Warn + `SIGNATURE_VERIFIER_USES_MIRROR_MARK_TODAY` Warn) |
| **R150 manifest entries** | 11 (5 cohort-rule pins + 5 upstream-emitter expected-surface refs + 1 parity marker) |
| **R150 ReviewerClasses** | 3 (`cohort_maintainer` / `emitter_author` / `founder_draft`) |
| **R166 legal footers** | 1 (DemoLiabilityFooter, founder-drafted) |
| **R166 ReviewedByCounsel** | **`false`** honest-default at module level |
| **CLI subcommands** | 6 (`run` / `advisories` / `footer` / `kat1` / `manifest` / `version`) |

## R-CROSS-INFRA-AUDIT-CHAIN-EMIT — what is being demonstrated

The Limitless cohort ships five infrastructure flagships that each emit signed receipts at trust boundaries:

- `delve` — emits a receipt when a schema-card lands at a database boundary.
- `grounded` — emits a receipt when a citation is retrieved from an authoritative corpus.
- `recall` — emits a receipt when a citation lookup is cached.
- `echo` — emits a receipt when an event is published.
- `parallax` — emits a receipt when a job is dispatched.

Individually each receipt is sound: an OpenSSL one-liner with the signer's public verification material proves "this signer attested to this payload at this time." But a regulator reading a single receipt cannot answer "what caused this?"

**`R-CROSS-INFRA-AUDIT-CHAIN-EMIT`** is the discipline of:

1. Each emitter includes a `prev_receipt_hash` field in its payload, chosen as the SHA-256 over the canonical bytes of the immediately-preceding receipt.
2. The receipts form a strictly-ordered, temporally-coherent sequence — receipt `R_i` is the cryptographic descendant of `R_{i-1}`.
3. The chain is bottom-up verifiable: a verifier walks from `R_1` forward, recomputing each `prev_receipt_hash` and re-verifying each signature, rejecting on the first failure.

Tampering with any receipt in the middle of the chain breaks either (a) the signature on that receipt (payload edited) or (b) the prev-hash on the next receipt (substitution detected).

This demo is the **1st saturator (1/3)** of the new R-rule. Cohort siblings (2nd + 3rd) are deferred to a follow-up M-slot.

## Architecture (Phase-1)

```
limitless-audit-chain-demo/
├── cmd/
│   └── audit-chain-demo/
│       └── main.go             (CLI: 6 subcommands incl. `run` end-to-end demo)
├── internal/
│   ├── chain/                  R-CROSS-INFRA-AUDIT-CHAIN-EMIT composition library — THE LOAD-BEARING PRIMITIVE
│   ├── emitters/               I20 stand-ins for delve / grounded / recall / echo / parallax
│   ├── lore/                   R151 KAT-1 hex pin
│   ├── mirrormark/             L43 Mirror-Mark v1 (placeholder signature surface)
│   ├── manifest/               R150 schematised knowledge envelope
│   ├── honest/                 R143 LOUD-ONCE-WARNING-FLAG
│   ├── firewall/               R145.C internal/ + cmd/ drift firewall
│   └── legal/                  R166 founder-drafted DemoLiabilityFooter + ReviewedByCounsel=false
├── tests/
│   └── audit_chain_test.go     End-to-end 5-step pipeline + chain verification test
├── docs/                       (Phase-2+ design docs go here)
├── go.mod                      github.com/davly/limitless-audit-chain-demo / go 1.22
├── .gitignore                  Go-flagship standard
├── LICENSE                     Apache-2.0
├── README.md                   Pitch + 5-step pipeline walkthrough
├── CONTEXT.md                  This file
└── SECURITY.md                 Demo-tier boundary doc
```

## I20 stand-in posture (honest disclosure)

At I20 ship-time the five upstream SDKs are being uplifted in parallel by the I3-I7 marathon agents:

- I3 → delve
- I4 → grounded
- I5 → recall
- I6 → echo
- I7 → parallax

Their `EmitXReceipt(payload, prev, ts)` surfaces have not yet stabilised. Per the I20 directive:

> "Approach (b) is preferred — write demo against expected surface; if I3-I7 land different shapes, the demo gets updated in a follow-up M-slot."

The `internal/emitters/` package ships stand-ins that:

1. Hash the supplied payload bytes with SHA-256.
2. Build a canonical `chain.Receipt` with the correct `SignerID` + `PrevReceiptHash` + `PayloadHash` + `Timestamp` fields.
3. Sign the receipt's `CanonicalBytes()` with the demo's Mirror-Mark primitive under a per-emitter corpus tag (so each emitter's signatures are distinguishable + a future dispatch verifier can route on `SignerID`).

Every stand-in function carries the literal `// I20-STAND-IN` comment so a future M-slot can grep-replace them.

## R174 5-of-5 maturity at launch

limitless-audit-chain-demo is a NEW repo at I20 launch with all 5 R174 cohort packages present from day one:

| Package | R-rule | Status at launch |
|---|---|---|
| `internal/lore/` | R151 | KAT-1 hex literal + Compute + ComputeFor + 7 tests |
| `internal/mirrormark/` | L43 | Sign + Verify + 5 tests covering roundtrip / tamper / wrong corpus / unknown prefix / malformed body |
| `internal/manifest/` | R150 | 11 entries (5 cohort + 5 emitters + 1 parity) + IsStale + 3-class ReviewerClass |
| `internal/honest/` | R143 | 3 Warn advisories + LoudOnce + Reset + concurrent-safe |
| `internal/firewall/` | R145.C | ExpectedPackages + ExpectedR174CorePackages + cmd/internal drift detection |

R174 5-of-5 verified by `TestFirewall_AllFiveR174CohortPackagesPresent` + `TestFirewall_R174CoreFivePackagesPresent`.

## Phase-1-refresh trigger

When **any of the following** lands, CONTEXT.md + SECURITY.md MUST be refreshed:

1. First real upstream SDK import (e.g. `import "github.com/davly/delve"`) replaces an `I20-STAND-IN` marker — drop the `UPSTREAM_SDK_STAND_INS_IN_USE` advisory severity to INFO once all five are replaced.
2. First per-emitter signature dispatch lands in `internal/chain/` — drop the `SIGNATURE_VERIFIER_USES_MIRROR_MARK_TODAY` advisory.
3. First HTTP listener (`http.ListenAndServe`) — Phase-2 HTTP API.
4. First DB persistence (`database/sql`) — chain durable-store.
5. First env-var read (`os.Getenv`) — production-key load.
6. First counsel-signoff flip (`ReviewedByCounsel = true`) — on its own R145.B sibling-not-stacked branch.
7. 2nd + 3rd `R-CROSS-INFRA-AUDIT-CHAIN-EMIT` saturator ships — promote R-rule from 1/3 to 3/3.

## Honest gaps (Phase-2 backlog)

1. **Stand-in emitters in `internal/emitters/`** — five SDK stand-ins remain in place until I3-I7 ship.
2. **No per-emitter signature dispatch** — the verifier is Mirror-Mark-uniform; per-emitter dispatch is a deferred uplift.
3. **No HTTP API** — Phase-1 is a CLI demonstration; Phase-2 would expose chain-build + chain-verify endpoints.
4. **No DB persistence** — chains are in-memory only; production hosts MUST persist to a write-once-read-many backing store.
5. **No counsel-reviewed legal bodies** — DemoLiabilityFooter is founder-drafted; ReviewedByCounsel = false honest baseline.
6. **Only 1/3 R-CROSS-INFRA-AUDIT-CHAIN-EMIT saturators** — this demo is 1st; 2nd + 3rd deferred.
