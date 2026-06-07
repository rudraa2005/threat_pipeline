package pipeline

import (
	"context"
	"testing"
	"threat_pipeline/data_ingestion/bloom"
	"threat_pipeline/data_ingestion/lsh"
	"threat_pipeline/data_ingestion/minhash"
	"threat_pipeline/data_ingestion/store"
)

func TestPipeline(t *testing.T) {
	ctx := context.Background()
	doc1 := Document{
		ID:   "",
		Body: "Malware detected in Engine C",
	}

	msh := minhash.New(200)
	lsh := lsh.New(20, 5)
	bf := bloom.New(958058, 7)
	mockRedis := store.NewMock()

	pipe := New(msh, bf, mockRedis, lsh)
	res1 := pipe.Process(ctx, &doc1)
	if res1.Action != "pass" {
		panic("Expcted alert")
	}
	t.Logf("Novel document found, Action: %v, Reason:%v", res1.Action, res1.Reason)
}

func TestExactDuplicate(t *testing.T) {
	ctx := context.Background()
	msh := minhash.New(200)
	lsh := lsh.New(20, 5)
	bf := bloom.New(958058, 7)
	mock := store.NewMock()
	pipe := New(msh, bf, mock, lsh)

	doc := &Document{Body: "Ransomware detected in Engine D", Indicators: []string{"D"}}

	r1 := pipe.Process(ctx, doc)
	r2 := pipe.Process(ctx, doc) // identical body

	if r1.Action != "pass" {
		t.Fatalf("first doc should pass, got: %s", r1.Action)
	}
	if r2.Action != "drop" {
		t.Fatalf("exact duplicate should drop, got: %s — reason: %s", r2.Action, r2.Reason)
	}
	t.Logf("r1: %s | r2: %s (%s)", r1.Action, r2.Action, r2.Reason)
}

func TestNearDuplicate(t *testing.T) {
	ctx := context.Background()
	msh := minhash.New(200)
	lsh := lsh.New(50, 2)
	bf := bloom.New(958058, 7)
	mock := store.NewMock()
	pipe := New(msh, bf, mock, lsh)

	doc1 := &Document{
		Body: "ransomware actors exploiting critical infrastructure using malicious payloads",
	}
	doc2 := &Document{
		Body: "ransomware group exploiting critical infrastructure using malicious tools",
	}

	r1 := pipe.Process(ctx, doc1)
	r2 := pipe.Process(ctx, doc2)

	if r1.Action != "pass" {
		t.Fatalf("first doc should pass, got: %s", r1.Action)
	}
	if r2.Action != "drop" {
		t.Fatalf("near-duplicate should drop, got: %s", r2.Action)
	}
	t.Logf("r1: %s | r2: %s (%s) candidates: %v", r1.Action, r2.Action, r2.Reason, r2.Candidates)
}
