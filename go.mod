module github.com/davly/limitless-audit-chain-demo

go 1.22

// Consume the cohort-canonical audit-chain SDK (SDK extraction #8)
// instead of the in-tree fork. The demo's internal/chain package is now
// a thin re-export shim over this module (see internal/chain/chain.go).
//
// The SDK is now published at github.com/davly/limitless-audit-chain
// (origin/main), so we pin a resolvable pseudo-version and drop the
// sibling-path `replace`. The local path replace (`=> ../../sdk/...`)
// broke single-repo CI: the GitHub Actions job does a one-repo checkout
// then `go build ./...`, so `../../sdk/limitless-audit-chain` did not
// exist on the runner and the build went RED (the `replace ../../*`
// footgun). The pinned pseudo-version below is `go list -m @latest` for
// the module and corresponds to SDK commit 236d522 on origin/main, which
// carries the exact pkg/chain surface internal/chain/chain.go re-exports.
require github.com/davly/limitless-audit-chain v0.0.0-20260604220632-236d52295e13

// NOTE on dependencies (I20, 2026-05-28 — INFRA marathon):
//
// The "expected" production composition imports five sibling SDKs:
//
//   github.com/davly/delve     // Step 1 — schema-card emitter
//   github.com/davly/grounded  // Step 2 — citation retrieval emitter
//   github.com/davly/recall    // Step 3 — citation cache emitter
//   github.com/davly/echo      // Step 4 — event emitter
//   github.com/davly/parallax  // Step 5 — job dispatch emitter
//
// At I20 ship-time those five flagships are still being uplifted in
// parallel (I3-I7) — their `Emit*Receipt` surfaces are not yet final.
// Per the I20 directive ("approach (b) is preferred — write demo
// against expected surface; if I3-I7 land different shapes, the demo
// gets updated in a follow-up M-slot") this demo ships with
// `internal/emitters/` carrying canonical-shape stand-ins that
// faithfully model the expected wire-format. The stand-ins are
// labelled `// I20-STAND-IN` so a future M-slot can grep-replace them
// when the five SDKs ship their receipt surfaces.
//
// Because the stand-ins are in `internal/emitters/`, the demo is
// fully testable in isolation today + the chain-composition library
// in `internal/chain/` is exercised end-to-end by the test suite.
//
// This is the canonical 1st saturator of
// R-CROSS-INFRA-AUDIT-CHAIN-EMIT — the load-bearing claim is the
// chain composition + verification, not the specific upstream
// emitter implementations.
