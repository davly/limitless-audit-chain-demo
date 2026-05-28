package mirrormark

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestSign_RoundTripsThroughVerify(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = byte(i)
	}
	payload := []byte("hello cross-infra audit chain")
	key := []byte("demo-key-bytes")
	mark := Sign(corpus, payload, key)
	if !strings.HasPrefix(mark, MarkPrefix) {
		t.Fatalf("mark missing prefix: %q", mark)
	}
	if err := Verify(mark, corpus, payload, key); err != nil {
		t.Fatalf("Verify roundtrip: %v", err)
	}
}

func TestVerify_TamperedPayloadRejected(t *testing.T) {
	var corpus [sha256.Size]byte
	payload := []byte("orig")
	key := []byte("k")
	mark := Sign(corpus, payload, key)
	if err := Verify(mark, corpus, []byte("tampered"), key); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("tampered payload: got %v, want ErrSignatureMismatch", err)
	}
}

func TestVerify_WrongCorpusRejected(t *testing.T) {
	var corpus1 [sha256.Size]byte
	var corpus2 [sha256.Size]byte
	corpus2[0] = 0x42
	mark := Sign(corpus1, []byte("x"), []byte("k"))
	if err := Verify(mark, corpus2, []byte("x"), []byte("k")); !errors.Is(err, ErrCorpusMismatch) {
		t.Fatalf("wrong corpus: got %v, want ErrCorpusMismatch", err)
	}
}

func TestVerify_UnknownPrefixRejected(t *testing.T) {
	var corpus [sha256.Size]byte
	if err := Verify("not-a-mark", corpus, nil, nil); !errors.Is(err, ErrUnknownMarkVersion) {
		t.Fatalf("unknown prefix: got %v, want ErrUnknownMarkVersion", err)
	}
}

func TestVerify_MalformedBodyRejected(t *testing.T) {
	var corpus [sha256.Size]byte
	if err := Verify(MarkPrefix+"!@#$not-base64$#@!", corpus, nil, nil); !errors.Is(err, ErrMalformedMark) {
		t.Fatalf("malformed body: got %v, want ErrMalformedMark", err)
	}
}
