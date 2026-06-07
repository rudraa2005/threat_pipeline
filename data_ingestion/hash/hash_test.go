package hash

import (
	"testing"
)

func TestDeterminism(t *testing.T) {
	_, h1 := Document("advanced persistence threat")
	_, h2 := Document("advanced persistence threat")

	if h1 != h2 {
		t.Fatal("same input produced different hashes")
	}
}
func TestAvalanche(t *testing.T) {
	_, h1 := Document("advanced persistence threat")
	_, h2 := Document("advanced persistence threat.")

	if h1 == h2 {
		t.Fatal("different inputs produced same hashes")
	}
}

func TestHexLength(t *testing.T) {
	_, h := Document("any input")
	if len(h) != 64 {
		t.Fatalf("expected 64 chars , got %d", len(h))
	}
}
