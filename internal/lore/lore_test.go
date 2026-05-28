package lore

import (
	"bytes"
	"testing"
)

func TestKAT1_DigestHexLiteral(t *testing.T) {
	got := Compute()
	if got != Digest {
		t.Fatalf("KAT-1 R151 firewall drift:\n  got:  %s\n  want: %s\n", got, Digest)
	}
}

func TestKAT1_DigestLength(t *testing.T) {
	if len(Digest) != 64 {
		t.Fatalf("KAT-1 Digest length: got %d, want 64", len(Digest))
	}
}

func TestKAT1_CanonicalInputShape(t *testing.T) {
	input := CanonicalInput()
	if len(input) != InputLen {
		t.Fatalf("CanonicalInput length: got %d, want %d", len(input), InputLen)
	}
	if input[0] != VersionTag {
		t.Fatalf("CanonicalInput[0]: got 0x%02x, want 0x%02x", input[0], VersionTag)
	}
	if input[0] != 0x01 {
		t.Fatalf("VersionTag: got 0x%02x, want 0x01", input[0])
	}
	for i := 1; i < InputLen; i++ {
		if input[i] != 0x00 {
			t.Fatalf("CanonicalInput[%d]: got 0x%02x, want 0x00", i, input[i])
		}
	}
}

func TestKAT1_CanonicalKeyEmpty(t *testing.T) {
	if len(CanonicalKey()) != 0 {
		t.Fatalf("CanonicalKey: got %d bytes, want 0", len(CanonicalKey()))
	}
}

func TestKAT1_DeterministicRoundTrip(t *testing.T) {
	first := Compute()
	for i := 0; i < 50; i++ {
		if got := Compute(); got != first {
			t.Fatalf("iter %d: non-deterministic", i)
		}
	}
}

func TestKAT1_ComputeFor_CanonicalAgreesWithCompute(t *testing.T) {
	want := Compute()
	got := ComputeFor(CanonicalInput(), CanonicalKey())
	if got != want {
		t.Fatalf("ComputeFor(canonical) != Compute():\n  ComputeFor: %s\n  Compute:    %s", got, want)
	}
}

func TestKAT1_ComputeFor_DifferentInputDifferentDigest(t *testing.T) {
	want := Compute()
	mutated := CanonicalInput()
	mutated[1] = 0x01
	if bytes.Equal(mutated, CanonicalInput()) {
		t.Fatalf("perturbation produced byte-identical input — test bug")
	}
	got := ComputeFor(mutated, CanonicalKey())
	if got == want {
		t.Fatalf("HMAC collision on single-bit flip — test bug")
	}
}
