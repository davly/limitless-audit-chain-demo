module github.com/davly/limitless-audit-chain-demo

go 1.22

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
