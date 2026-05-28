// Package legal pins limitless-audit-chain-demo's founder-drafted
// liability disclaimer + the R166 ReviewedByCounsel honest-default
// sentinel.
//
// limitless-audit-chain-demo joins the founder-drafted legal-document
// cohort (R166 R-LIABILITY-FOOTER-CONST + REVIEWED-BY-COUNSEL-FALSE)
// because it ships as the canonical 1st saturator of
// R-CROSS-INFRA-AUDIT-CHAIN-EMIT — a regulator-grade demonstration
// artefact whose footer text MUST be:
//
//  1. A typed constant in domain code (this file's
//     DemoLiabilityFooter), NEVER a string literal inlined at the
//     call site. Grep-discoverable, version-controlled.
//  2. Paired with `ReviewedByCounsel: bool = false` module-level
//     honest-default sentinel. False is load-bearing.
//  3. Documented in CONTEXT.md as founder-authored,
//     LIBRARY-RECOMMENDS-HOST-ACTS pattern.
package legal

// LegalDocumentVersion — bumping requires paired R145.B sibling
// branch.
const LegalDocumentVersion = "v1"

// EffectiveDate — pinned at module load. ISO 8601.
const EffectiveDate = "2026-05-28"

// ReviewedByCounsel is the R166 honest-default sentinel.
//
// FALSE is the load-bearing default. Flipping to True is a behaviour-
// changing event that MUST land on its own R145.B sibling-not-stacked
// branch with a named counsel signoff in the commit message.
const ReviewedByCounsel bool = false

// DemoLiabilityFooter is the canonical founder-drafted liability
// footer rendered into every demo output banner + the README +
// the CLI's `footer` subcommand.
const DemoLiabilityFooter = `=== limitless-audit-chain-demo v1 Demo Liability Footer ===

limitless-audit-chain-demo is the canonical 1st saturator of the
cohort R-CROSS-INFRA-AUDIT-CHAIN-EMIT discipline. It demonstrates
how five independent emitter SDKs (delve / grounded / recall /
echo / parallax) can have their per-step receipts composed into a
single tamper-evident audit chain that an external regulator can
cold-verify via OpenSSL.

THIS REPOSITORY IS A SHOWCASE DEMO — NOT A PRODUCTION RUNTIME.

Production deployments MUST replace the I20 stand-in emitters in
internal/emitters/ with the real upstream SDK calls once those
flagships ship. The chain composition library in internal/chain/
is the load-bearing primitive that survives the swap unchanged.

The signature surface at I20 ship-time uses the cohort Mirror-Mark
HMAC-SHA256 primitive as a unified placeholder for all five upstream
signatures. A future M-slot will introduce a dispatch verifier that
selects the per-emitter signature primitive based on the receipt's
SignerID field. The wire-format of Receipt is forward-compatible —
the Signature field is a typed string that any signature primitive
can populate.

This demo is founder-drafted and has NOT been reviewed by counsel
(R166 honest baseline: ReviewedByCounsel = false). The discipline
of the cohort R-rules in this footer (R143 / R145.C / R150 / R151 /
R166 / R174 / R175 / R-CROSS-INFRA-AUDIT-CHAIN-EMIT) is internal
cohort engineering discipline — not legal advice. A regulator
reading a chain produced by this demo gets a tamper-evident audit
trail; they do NOT get a representation about the underlying
business activity, the suitability of the chained operations for
any regulatory regime, or the legal sufficiency of the chain for
any specific audit purpose. Those determinations require qualified
counsel + a substantive review of the specific deployment.

No representation is made that the demo, on its own, satisfies any
regulatory requirement. Use of the chain composition primitive in
a regulated runtime is the responsibility of the deploying party.

(end of footer)
`
