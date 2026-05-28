# limitless-audit-chain-demo — Security Boundaries

*5-boundary PURE-GO-CLI-MINIMAL-COMPOSITE variant. I20 baseline (2026-05-28 INFRA marathon).*

Per the cohort SECURITY.md template the boundaries describe what crosses + what doesn't, the threat model at each boundary, and the honest disclosure of which boundaries are NOT yet wired.

## Threat model context

limitless-audit-chain-demo is a **showcase demo**, not a production runtime. The threat model below is the **target** posture once the upstream SDKs ship + the demo wires through to real emitter signature surfaces. At I20 ship-time, the relevant property is that the **chain composition library in `internal/chain/`** is sound: tampering with any receipt is detected by `Verify`.

## Boundary 1 — Process boundary (CLI invocation)

The demo runs as a CLI binary (`audit-chain-demo`). Inputs are:

- Command-line arguments (`os.Args`)
- (none — no stdin reads at I20)
- (none — no env-var reads at I20)

Outputs are:

- stdout (chain trace, manifest dump, footer text, KAT-1 hex)
- stderr (LOUD-ONCE-WARN advisories + errors)
- exit code (0 = success, 2 = usage error, 3 = runtime failure)

Threat: a malicious command-line argument cannot escalate beyond the demo's pure-Go boundaries. No `exec` calls, no shell-out.

## Boundary 2 — Signature surface (Mirror-Mark today)

At I20 ship-time, every emitted receipt is signed with Mirror-Mark HMAC-SHA256 under a **per-emitter corpus tag** + the demo's signing key (`internal/emitters.DemoSigningKey()`).

The signing key is a **literal byte slice** in `internal/emitters/emitters.go` — NOT a production secret. The demo is a showcase; signatures verify only against the demo's own verifier.

Threat: an external party reading the demo source can re-sign arbitrary receipts. This is INTENTIONAL — the demo's showcase value is the chain composition + verification primitive, not signature secrecy. Production runtimes will use the upstream SDK signature surfaces.

## Boundary 3 — Chain composition surface

The `internal/chain/` package is the load-bearing primitive. The relevant security property is:

> **Given a chain of N receipts each signed by an emitter, `Verify` returns `nil` iff (a) every receipt's signature verifies under the supplied `VerifierFunc`, (b) every non-genesis receipt's `PrevReceiptHash` equals `SHA-256` over the predecessor's `CanonicalBytes()`, and (c) every receipt's timestamp is `>=` predecessor's timestamp.**

Tampering modes detected:
- Payload edit on receipt `R_i` → `SHA-256(R_i.CanonicalBytes())` changes → `R_{i+1}.PrevReceiptHash` no longer matches → `ErrPrevHashMismatch`.
- Receipt substitution → either the substitute's prev-hash mismatches OR the substitute's signature fails.
- Signer-ID swap (without re-signing) → signature verifier rejects via per-emitter corpus tag.
- Timestamp inversion → `ErrTimestampInverted`.
- Empty chain / missing genesis / unknown signer / empty signature → typed sentinel errors.

## Boundary 4 — Stand-in emitter surface (I20 ship-time)

The five emitter stand-ins in `internal/emitters/` are **labelled** `// I20-STAND-IN`. They:

- DO sign receipts with Mirror-Mark + per-emitter corpus tag (so the chain composition + verification surface is fully exercised end-to-end).
- DO NOT call any real upstream SDK (delve / grounded / recall / echo / parallax are not yet `import`-able at I20 ship-time).
- DO NOT hold any production credentials.

The next M-slot uplift replaces each stand-in with the real upstream SDK call. The chain library survives the swap unchanged.

## Boundary 5 — No persistence

I20 ship-time: chains are **in-memory only**. The demo binary does not read or write any file beyond stdout/stderr.

Production hosts deploying the chain library MUST persist chains to a write-once-read-many backing store (S3 Object Lock / Postgres append-only schema). The chain library does NOT itself enforce persistence — that is the deploying host's responsibility (LIBRARY-RECOMMENDS-HOST-ACTS).

## Honest gaps (deferred uplifts)

| Gap | Resolves when |
|---|---|
| Demo signing key is a literal in source | Production runtimes use upstream SDK signatures + their own per-tenant keys. |
| All emitter calls go through Mirror-Mark | Per-emitter signature dispatch lands in `internal/chain/Verify`. |
| Stand-in emitters in `internal/emitters/` | I3-I7 upstream SDKs ship; grep-replace `I20-STAND-IN` markers. |
| In-memory only | Production hosts persist chains to write-once backing store. |
| ReviewedByCounsel = false | A counsel-reviewed flip lands on its own R145.B sibling-not-stacked branch with named counsel signoff. |
