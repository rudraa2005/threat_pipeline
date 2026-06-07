package lsh

import (
	"testing"
	"threat_pipeline/data_ingestion/minhash"
)

func TestLSHCandidates(t *testing.T) {
	m := minhash.New(100) // 100 hashes
	idx := New(20, 5)     // 20 bands of 5 rows

	docs := []struct{ id, text string }{
		{"doc1", "ransomware actors exploiting critical infrastructure power grid"},
		{"doc2", "ransomware group exploiting critical infrastructure power systems"}, // near-dup of doc1
		{"doc3", "weather patterns across the indian subcontinent this monsoon"},      // unrelated
	}

	// Index all docs
	for _, d := range docs {
		sig := m.Signature(d.text)
		idx.Add(d.id, sig)
	}

	// Query with near-dup of doc1
	querySig := m.Signature("ransomware threat actors exploiting critical infrastructure")
	candidates := idx.Query(querySig)

	t.Logf("candidates found: %v", candidates)

	// doc1 and doc2 should be candidates, doc3 should not
	foundDoc1, foundDoc3 := false, false
	for _, c := range candidates {
		if c == "doc1" {
			foundDoc1 = true
		}
		if c == "doc3" {
			foundDoc3 = true
		}
	}
	if !foundDoc1 {
		t.Error("doc1 should be a candidate")
	}
	if foundDoc3 {
		t.Error("doc3 should not be a candidate")
	}
}
