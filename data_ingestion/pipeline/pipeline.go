package pipeline

import (
	"context"
	"log"
	"threat_pipeline/data_ingestion/bloom"
	"threat_pipeline/data_ingestion/hash"
	"threat_pipeline/data_ingestion/lsh"
	"threat_pipeline/data_ingestion/minhash"
	"threat_pipeline/data_ingestion/store"
)

type Pipeline struct {
	bloom     *bloom.BloomFilter
	hashstore store.Storage
	lsh       *lsh.Index
	hasher    *minhash.MinHasher
}
type Result struct {
	Action     string
	Reason     string
	Candidates []string
}

type Document struct {
	ID         string
	Body       string
	Indicators []string
}

func New(mh *minhash.MinHasher, bl *bloom.BloomFilter, st store.Storage, lsh *lsh.Index) *Pipeline {
	return &Pipeline{
		bloom:     bl,
		lsh:       lsh,
		hashstore: st,
		hasher:    mh,
	}
}

func (p *Pipeline) Process(ctx context.Context, doc *Document) Result {
	rawhash, hashStr := hash.Document(doc.Body)

	if !p.bloom.TestAndAdd(rawhash) {

		doc.ID = hashStr
		_ = p.hashstore.Add(ctx, hashStr)
		sig := p.hasher.Signature(doc.Body)
		candidates := p.lsh.Query(sig)
		if len(candidates) > 0 && !hasNewIndicators(doc) {
			return Result{Action: "drop", Reason: "Near duplicate found", Candidates: candidates}
		}
		p.lsh.Add(doc.ID, sig)
		return Result{Action: "pass", Reason: "New"}
	}

	exists, err := p.hashstore.Exists(ctx, hashStr)
	if err != nil {
		log.Printf("Redis error: %s", err)
		sig := p.hasher.Signature(doc.Body)
		candidates := p.lsh.Query(sig)
		if len(candidates) > 0 && !hasNewIndicators(doc) {
			return Result{Action: "drop", Reason: "near duplicate found", Candidates: candidates}
		}
		p.lsh.Add(doc.ID, sig)
		return Result{Action: "pass", Reason: "redis down, treated as novel"}
	}
	if exists {
		return Result{Action: "drop", Reason: "exact duplicate"}
	} else {
		p.hashstore.Add(ctx, hashStr)
	}

	sig := p.hasher.Signature(doc.Body)
	candidates := p.lsh.Query(sig)
	if len(candidates) > 0 && !hasNewIndicators(doc) {
		return Result{
			Action:     "drop",
			Reason:     "near duplicate",
			Candidates: candidates,
		}
	}
	p.lsh.Add(doc.ID, sig)
	return Result{Action: "pass", Reason: "novel document"}
}

func hasNewIndicators(doc *Document) bool {
	return len(doc.Indicators) > 0
}
