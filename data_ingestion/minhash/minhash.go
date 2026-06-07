package minhash

import (
	"math"
	"strings"
)

type MinHasher struct {
	seeds     []uint64 // offset value, it is []uint64 because we need to iterate through different seed values for different hash functions
	numHashes int      // no. of hash functions (default - 100 or 200)
}

func New(numHashes int) *MinHasher {
	seeds := make([]uint64, numHashes)
	for i := range seeds {
		seeds[i] = uint64(i)*2654435761 + 1 //Knuth's Multiplicative hash seeds
	}
	return &MinHasher{seeds: seeds, numHashes: numHashes}
}

func hashUsingSeeds(data []byte, seed uint64) uint64 {
	const prime uint64 = 1099511628211
	h := seed
	for _, b := range data {
		h ^= uint64(b)
		h *= prime
	}
	return h
}

func tokenize(text string) []string {
	return strings.Fields(strings.ToLower(text))
}

func (m *MinHasher) Signature(text string) []uint64 {
	words := tokenize(text)
	sig := make([]uint64, m.numHashes)
	for i := range sig {
		sig[i] = math.MaxUint64
	}

	for _, word := range words {
		wb := make([]byte, len(word))
		copy(wb, word)
		for i, seed := range m.seeds {
			h := hashUsingSeeds(wb, seed)
			if h < sig[i] {
				sig[i] = h
			}
		}
	}
	return sig
}

func EstimateJaccard(sigA, sigB []uint64) float64 {
	if len(sigA) != len(sigB) {
		panic("signature length is different")
	}
	matches := 0

	for i := range sigA {
		if sigA[i] == sigB[i] {
			matches++
		}
	}
	return float64(matches) / float64(len(sigA))
}
