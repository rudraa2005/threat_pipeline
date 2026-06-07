// bloom/bloom_test.go
package bloom

import (
	"fmt"
	"testing"
)

func BenchmarkTestAndAdd(b *testing.B) {
	bf := New(9585058, 7)

	keys := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = []byte(fmt.Sprintf("threat-indicator-payload-%d", i))
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		bf.TestAndAdd(keys[i])
	}
}

func TestBloomBasic(t *testing.T) {
	bf := New(958058, 7)
	data := []byte("test input")

	first := bf.TestAndAdd(data)
	second := bf.TestAndAdd(data)

	if first {
		t.Fatal("first call should return false (definitely new)")
	}
	if !second {
		t.Fatal("second call should return true (already present)")
	}
}
