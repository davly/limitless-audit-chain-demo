// Package mirrormark implements the cohort L43 Mirror-Mark v1 receipt
// algorithm — byte-identical to foundation/pkg/mirrormark and to every
// cohort Go port.
//
// In limitless-audit-chain-demo, Mirror-Mark serves as the I20 ship-
// time placeholder for the five upstream emitters' signature surfaces.
// When delve / grounded / recall / echo / parallax land their
// per-emitter signature primitives, the demo's chain verifier will
// dispatch on Receipt.SignerID; today every receipt is Mirror-Mark-
// signed under the demo's KAT-1 keying.
//
// Mark format (byte-identical to foundation/pkg/mirrormark):
//
//	"lore@v1:" + base64url( corpusSHA[:8] || hmacSHA256(0x01 || corpusSHA || payload, key) )
package mirrormark

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const MarkVersion byte = 0x01
const MarkPrefix = "lore@v1:"
const MarkCorpusPrefixLen = 8
const MarkBodyLen = MarkCorpusPrefixLen + sha256.Size

var ErrUnknownMarkVersion = errors.New("mirrormark: unknown mark version (missing 'lore@v1:' prefix)")
var ErrMalformedMark = errors.New("mirrormark: malformed mark (base64url decode failed or wrong body length)")
var ErrCorpusMismatch = errors.New("mirrormark: corpus prefix mismatch")
var ErrSignatureMismatch = errors.New("mirrormark: HMAC signature mismatch")

func Sign(corpusSHA [sha256.Size]byte, payload []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte{MarkVersion})
	_, _ = mac.Write(corpusSHA[:])
	_, _ = mac.Write(payload)
	digest := mac.Sum(nil)

	body := make([]byte, 0, MarkBodyLen)
	body = append(body, corpusSHA[:MarkCorpusPrefixLen]...)
	body = append(body, digest...)

	return MarkPrefix + base64.RawURLEncoding.EncodeToString(body)
}

func Verify(mark string, corpusSHA [sha256.Size]byte, payload []byte, key []byte) error {
	if len(mark) < len(MarkPrefix) || mark[:len(MarkPrefix)] != MarkPrefix {
		return ErrUnknownMarkVersion
	}
	body, err := base64.RawURLEncoding.DecodeString(mark[len(MarkPrefix):])
	if err != nil {
		return ErrMalformedMark
	}
	if len(body) != MarkBodyLen {
		return ErrMalformedMark
	}
	corpusPrefix := body[:MarkCorpusPrefixLen]
	digest := body[MarkCorpusPrefixLen:]
	if !hmac.Equal(corpusPrefix, corpusSHA[:MarkCorpusPrefixLen]) {
		return ErrCorpusMismatch
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte{MarkVersion})
	_, _ = mac.Write(corpusSHA[:])
	_, _ = mac.Write(payload)
	want := mac.Sum(nil)
	if !hmac.Equal(digest, want) {
		return ErrSignatureMismatch
	}
	return nil
}
