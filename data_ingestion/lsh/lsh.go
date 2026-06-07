package lsh

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
)

type Index struct {
	bands  int
	rows   int
	bucket map[string][]string
	mu     sync.RWMutex
}

func New(bands, rows int) *Index {
	return &Index{
		bands:  bands,
		rows:   rows,
		bucket: make(map[string][]string),
	}
}

func (idx *Index) bucketKey(band int, bandSig []uint64) string {
	h := sha256.New()
	var buf [8]byte

	binary.LittleEndian.PutUint64(buf[:], uint64(band))
	h.Write(buf[:])

	for _, v := range bandSig {
		binary.LittleEndian.PutUint64(buf[:], v)
		h.Write(buf[:])
	}

	return hex.EncodeToString(h.Sum(nil)[:8])
}

func (idx *Index) Query(sig []uint64) []string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	seen := make(map[string]bool)
	var candidates []string

	for b := 0; b < idx.bands; b++ {
		start := b * idx.rows
		end := start + idx.rows
		key := idx.bucketKey(b, sig[start:end])
		for _, docID := range idx.bucket[key] {
			if !seen[docID] {
				seen[docID] = true
				candidates = append(candidates, docID)
			}
		}
	}
	return candidates
}

func (idx *Index) Add(docID string, sig []uint64) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	for b := 0; b < idx.bands; b++ {
		start := b * idx.rows
		end := start + idx.rows
		key := idx.bucketKey(b, sig[start:end])

		idx.bucket[key] = append(idx.bucket[key], docID)
	}
}
