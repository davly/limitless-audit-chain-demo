# limitless-audit-chain-demo

**The canonical 1st saturator of `R-CROSS-INFRA-AUDIT-CHAIN-EMIT` — a customer-grade showcase that composes signed receipts from five independent emitter SDKs into a single tamper-evident audit chain.**

This is a SHOWCASE DEMO of the Limitless ecosystem's cross-infrastructure audit-chain discipline — NOT a production runtime. See `internal/legal/legal.go` for the founder-drafted disclaimer.

## The 5-step pipeline

```
  Step 1   delve     → emits R1 (schema-card,             genesis receipt)
                          PrevReceiptHash = 0000...0000
  Step 2   grounded  → emits R2 (citation retrieval,      chains R1)
                          PrevReceiptHash = SHA-256(R1.CanonicalBytes())
  Step 3   recall    → emits R3 (citation lookup cache,   chains R2)
                          PrevReceiptHash = SHA-256(R2.CanonicalBytes())
  Step 4   echo      → emits R4 (event publication,       chains R3)
                          PrevReceiptHash = SHA-256(R3.CanonicalBytes())
  Step 5   parallax  → emits R5 (job dispatch,            chains R4)
                          PrevReceiptHash = SHA-256(R4.CanonicalBytes())
```

Each receipt is signed by its own emitter. The chain is **bottom-up verifiable**: a verifier walks from R1 forward, recomputing each `prev_receipt_hash` and re-verifying each signature, and rejects the chain if any step fails.

## Why this matters

Individually, each emitter's receipt is sound — an OpenSSL one-liner with the signer's verification material proves "this signer attested to this payload at this time." But a regulator reading a single receipt cannot answer "what caused this?" The receipts are atomic, not composable.

`R-CROSS-INFRA-AUDIT-CHAIN-EMIT` is the discipline of:

1. Each emitter includes a `prev_receipt_hash` field in its payload, chosen as the SHA-256 over the canonical bytes of the immediately-preceding receipt.
2. The receipts form a strictly-ordered, temporally-coherent sequence.
3. The chain is bottom-up verifiable — tampering with any receipt in the middle breaks either the signature (if the payload was edited) or the prev-hash of the next receipt (if the receipt was substituted).

The chain is therefore **tamper-evident as a composite**, even though each individual receipt is independently signed by a different emitter.

## Run the demo

```bash
go build -o audit-chain-demo ./cmd/audit-chain-demo
./audit-chain-demo run
```

Expected output (after the boot-time LOUD-ONCE-WARN advisories):

```
R-CROSS-INFRA-AUDIT-CHAIN-EMIT — 5-step pipeline

  [R1] signer=delve      payload_hash=<hex-prefix>...
       prev_hash   =0000000000000000...0000
       timestamp   =2026-05-28T12:00:00Z
       signature   =lore@v1:<base64url>

  [R2] signer=grounded   payload_hash=<hex-prefix>...
       prev_hash   =<sha256 of R1.CanonicalBytes()>
       ...

  [R3..R5] ...

Chain verification: PASS  (5/5 receipts verified, 4/4 prev-hash links intact)
Signer sequence: [delve grounded recall echo parallax]
```

## Run the tests

```bash
go test ./...
```

End-to-end tests live in `tests/audit_chain_test.go`. Unit tests live alongside each package in `internal/`.

## Cohort discipline (R174 5-of-5 from inception)

This demo ships the canonical R174 cohort packages from day one:

| Package | R-rule | Purpose |
|---|---|---|
| `internal/lore/` | R151 | KAT-1 HMAC-SHA256 hex pin |
| `internal/mirrormark/` | L43 | Cohort Mirror-Mark Sign/Verify (placeholder signature surface) |
| `internal/manifest/` | R150 | R150 schematised-knowledge envelope (11 entries) |
| `internal/honest/` | R143 | LOUD-ONCE-WARNING-FLAG advisories (3 Warn entries) |
| `internal/firewall/` | R145.C | internal/ + cmd/ drift firewall |

Plus three demo-specific packages:

| Package | R-rule | Purpose |
|---|---|---|
| `internal/chain/` | R-CROSS-INFRA-AUDIT-CHAIN-EMIT | **The load-bearing composition library** |
| `internal/emitters/` | (I20 stand-ins) | Stand-in implementations of delve / grounded / recall / echo / parallax |
| `internal/legal/` | R166 | Founder-drafted liability footer + ReviewedByCounsel = false |

## I20 ship-time scope (honest disclosure)

At I20 ship-time (2026-05-28), the five upstream emitter SDKs are being uplifted in parallel by the I3-I7 marathon agents. Their `EmitXReceipt(payload, prev, ts)` surfaces have not yet stabilised.

Per the I20 directive:

> "Approach (b) is preferred — write demo against expected surface; if I3-I7 land different shapes, the demo gets updated in a follow-up M-slot."

The `internal/emitters/` package ships stand-ins that faithfully model the expected wire-format. Every stand-in function is marked with the literal `// I20-STAND-IN` comment so a future M-slot can grep-replace them when the upstream surfaces stabilise.

The chain composition library in `internal/chain/` is the load-bearing primitive — it survives the I20 → real-SDK swap unchanged.

## KAT-1 cold-verify (regulator-grade)

A regulator with `openssl dgst` can verify the cohort substrate without a Go toolchain:

```bash
printf '\x01' > /tmp/kat1.bin
printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
# → HMAC-SHA256(stdin) = 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

The same hex is pinned in `internal/lore/lore.go` and verified by `lore_test.go`.

```bash
./audit-chain-demo kat1
```

## Cohort siblings

- [`canopy`](https://github.com/davly/canopy) (Go) — runtime NYC LL144 + EEOC R74 dual-gate.
- [`bias-audit`](https://github.com/davly/bias-audit) (Go) — SaaS productisation of NYC LL144 AEDT (R174 cohort precedent).
- [`memoria`](https://github.com/davly/memoria) (Go) — first R174 5-of-5 from inception.
- [`conjure`](https://github.com/davly/conjure) (TypeScript) — first non-Go R174 5-of-5 from inception.
- [`folio`](https://github.com/davly/folio) / [`casino`](https://github.com/davly/casino) / [`ledger`](https://github.com/davly/ledger) — Mirror-Mark wired-in-production cohort.

## License

Apache-2.0. See `LICENSE`.

## Status

| Field | Value |
|---|---|
| Phase | **Phase-1 scaffold + showcase (I20 ship, 2026-05-28 INFRA marathon)** |
| Primary language | Go 1.22 |
| Tests | `go test ./...` GREEN at I20 ship |
| R174 5-of-5 | yes, from inception (lore + mirrormark + manifest + honest + firewall) |
| R166 cohort | joined as 12th+ instance (founder-drafted DemoLiabilityFooter + ReviewedByCounsel = false) |
| R-CROSS-INFRA-AUDIT-CHAIN-EMIT | **1st saturator (1/3)** — promotion gate |
| Upstream SDK dependencies | none yet (I20 stand-ins in `internal/emitters/`); replace in follow-up M-slot |
| Counsel-reviewed | no (founder-drafted; R166 honest-default) |
