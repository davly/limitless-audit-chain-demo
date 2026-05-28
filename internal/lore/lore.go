// Package lore pins the ecosystem-canonical KAT-1 HMAC-SHA256
// invariant for the R151 ECOSYSTEM_QUALITY_STANDARD.md Part XII
// cross-substrate pin.
//
// limitless-audit-chain-demo is the canonical 1st saturator of
// R-CROSS-INFRA-AUDIT-CHAIN-EMIT. It consumes the cohort KAT-1
// invariant identically to every other R174 5-of-5 flagship — a
// regulator (or downstream auditor) verifying a five-step chain
// against the OpenSSL one-liner can confirm at line 0 that the
// HMAC-SHA256 substrate underneath the chain is the same one
// pinned across the entire cohort.
//
// Cold-verify recipe (OpenSSL one-liner — no Go toolchain involved):
//
//	# KAT-1 input: 0x01 || 32×0x00 (33 bytes); HMAC key: empty
//	printf '\x01' > /tmp/kat1.bin
//	printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
//	openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
//	# → HMAC-SHA256(stdin) = 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
package lore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Digest is the cohort-canonical KAT-1 HMAC-SHA256 digest, hex-encoded.
// Pinned byte-identical to foundation/pkg/mirrormark.KAT1Digest and to
// every cohort port.
const Digest = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

// InputLen is the canonical KAT-1 input length: 1 byte version tag +
// 32 bytes zero corpus = 33 bytes.
const InputLen = 33

// VersionTag is the v1 1-byte tag prefix.
const VersionTag byte = 0x01

// CanonicalInput returns the cohort-canonical 33-byte KAT-1 input.
func CanonicalInput() []byte {
	out := make([]byte, InputLen)
	out[0] = VersionTag
	return out
}

// CanonicalKey returns the cohort-canonical KAT-1 HMAC key: empty.
func CanonicalKey() []byte { return []byte{} }

// Compute returns the HMAC-SHA256 hex digest for the cohort-canonical
// KAT-1 input + key. MUST byte-equal Digest.
func Compute() string {
	mac := hmac.New(sha256.New, CanonicalKey())
	_, _ = mac.Write(CanonicalInput())
	return hex.EncodeToString(mac.Sum(nil))
}

// ComputeFor returns the HMAC-SHA256 hex digest for an arbitrary
// (input, key) pair.
func ComputeFor(input []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(input)
	return hex.EncodeToString(mac.Sum(nil))
}
