// Package emitters contains I20 stand-in implementations of the five
// upstream emitter SDKs (delve / grounded / recall / echo / parallax).
//
// # Why this package exists
//
// At I20 ship-time the five SDKs are being uplifted in parallel by
// the I3-I7 marathon agents. Their `EmitXReceipt(payload, prev, ts)`
// surfaces have not yet stabilised. Per the I20 directive
// ("approach (b) is preferred — write demo against expected surface;
// if I3-I7 land different shapes, the demo gets updated in a
// follow-up M-slot") this package ships stand-ins that faithfully
// model the expected wire-format so the demo's chain composition
// + verification + tests all run end-to-end today.
//
// # I20-STAND-IN markers
//
// Every function in this package is marked with the magic
// `// I20-STAND-IN` literal comment so a future M-slot can grep
// the codebase + swap each stand-in for the real upstream SDK call
// once the upstream surfaces stabilise.
//
// # Honest behaviour
//
// The stand-ins are NOT no-op fakes. Each one:
//
//  1. Hashes the supplied payload bytes with SHA-256.
//  2. Builds a canonical chain.Receipt with the correct SignerID +
//     PrevReceiptHash + PayloadHash + Timestamp fields.
//  3. Signs the receipt's CanonicalBytes() with the demo's
//     Mirror-Mark primitive under a per-emitter corpus tag (so
//     each emitter's signatures are distinguishable + a future
//     dispatch verifier can route on SignerID).
//
// The resulting receipts pass chain.Verify(MirrorMarkVerifier) and
// chain into a single tamper-evident audit trail — the
// load-bearing demonstration.
package emitters

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/davly/limitless-audit-chain-demo/internal/chain"
	"github.com/davly/limitless-audit-chain-demo/internal/mirrormark"
)

// CorpusFor returns a deterministic per-emitter corpus SHA. Used so
// that each emitter's signatures are distinguishable + so a future
// M-slot dispatch verifier can recognise the per-emitter signature
// stand-in cleanly.
func CorpusFor(signer chain.SignerID) [sha256.Size]byte {
	sum := sha256.Sum256([]byte("limitless-audit-chain-demo/I20/corpus/" + string(signer)))
	return sum
}

// DemoSigningKey returns the demo's HMAC signing key. NOT a
// production secret — the demo's signatures verify against the
// `MirrorMarkVerifier` returned below.
func DemoSigningKey() []byte {
	return []byte("limitless-audit-chain-demo/I20/demo-key")
}

// PayloadHash returns the hex SHA-256 of a payload byte slice.
func PayloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// EmitDelveReceipt — Step 1 stand-in for github.com/davly/delve.
//
// I20-STAND-IN: delve will emit a receipt when a schema-card lands at
// a database boundary. The expected production surface mirrors this
// function; when I3 lands the real surface, replace this body with a
// call to `delve.EmitSchemaCardReceipt(payload, prev, ts)`.
func EmitDelveReceipt(payload []byte, prevHash string, ts time.Time) chain.Receipt {
	return signedReceipt(chain.SignerDelve, payload, prevHash, ts)
}

// EmitGroundedReceipt — Step 2 stand-in for github.com/davly/grounded.
//
// I20-STAND-IN: grounded will emit a receipt when a citation is
// retrieved from an authoritative corpus. When I4 lands the real
// surface, replace this body with a call to
// `grounded.EmitCitationReceipt(payload, prev, ts)`.
func EmitGroundedReceipt(payload []byte, prevHash string, ts time.Time) chain.Receipt {
	return signedReceipt(chain.SignerGrounded, payload, prevHash, ts)
}

// EmitRecallReceipt — Step 3 stand-in for github.com/davly/recall.
//
// I20-STAND-IN: recall will emit a receipt when a citation lookup is
// cached. When I5 lands the real surface, replace this body with a
// call to `recall.EmitCacheReceipt(payload, prev, ts)`.
func EmitRecallReceipt(payload []byte, prevHash string, ts time.Time) chain.Receipt {
	return signedReceipt(chain.SignerRecall, payload, prevHash, ts)
}

// EmitEchoReceipt — Step 4 stand-in for github.com/davly/echo.
//
// I20-STAND-IN: echo will emit a receipt when an event is published.
// When I6 lands the real surface, replace this body with a call to
// `echo.EmitEventReceipt(payload, prev, ts)`.
func EmitEchoReceipt(payload []byte, prevHash string, ts time.Time) chain.Receipt {
	return signedReceipt(chain.SignerEcho, payload, prevHash, ts)
}

// EmitParallaxReceipt — Step 5 stand-in for github.com/davly/parallax.
//
// I20-STAND-IN: parallax will emit a receipt when a job is dispatched.
// When I7 lands the real surface, replace this body with a call to
// `parallax.EmitJobDispatchReceipt(payload, prev, ts)`.
func EmitParallaxReceipt(payload []byte, prevHash string, ts time.Time) chain.Receipt {
	return signedReceipt(chain.SignerParallax, payload, prevHash, ts)
}

func signedReceipt(signer chain.SignerID, payload []byte, prevHash string, ts time.Time) chain.Receipt {
	r := chain.Receipt{
		PrevReceiptHash: prevHash,
		PayloadHash:     PayloadHash(payload),
		SignerID:        signer,
		Timestamp:       ts.UTC(),
	}
	corpus := CorpusFor(signer)
	r.Signature = mirrormark.Sign(corpus, r.CanonicalBytes(), DemoSigningKey())
	return r
}

// MirrorMarkVerifier returns a chain.VerifierFunc that verifies a
// receipt's Mirror-Mark signature under the per-emitter corpus tag
// returned by CorpusFor + the demo signing key.
//
// I20-STAND-IN: when the upstream SDKs land their per-emitter
// signature surfaces, this returns a dispatch verifier that selects
// the per-emitter signature primitive based on Receipt.SignerID.
func MirrorMarkVerifier() chain.VerifierFunc {
	key := DemoSigningKey()
	return func(r chain.Receipt) error {
		corpus := CorpusFor(r.SignerID)
		return mirrormark.Verify(r.Signature, corpus, r.CanonicalBytes(), key)
	}
}
