package orchestrator

import (
	"context"
	"fmt"
	"testing"
	"threat_pipeline/crawler/client"
	"threat_pipeline/crawler/fetcher"

	ratelimiter "threat_pipeline/crawler/rateLimiter"
	"threat_pipeline/data_ingestion/bloom"
	"threat_pipeline/data_ingestion/lsh"
	"threat_pipeline/data_ingestion/minhash"
	"threat_pipeline/data_ingestion/pipeline"
	"threat_pipeline/data_ingestion/store"
	"time"
)

func TestOrchestratorStreamingResults(t *testing.T) {
	ctx := context.Background()
	c := client.NewClearnet()
	f := fetcher.New(c)
	l := ratelimiter.New(5, 5)

	msh := minhash.New(200)
	lshIdx := lsh.New(50, 2)
	bf := bloom.New(958058, 7)
	mock := store.NewMock()
	pipe := pipeline.New(msh, bf, mock, lshIdx)

	orch := New(f, l, pipe, 3, 5*1024*1024)

	produce := func(ctx context.Context, out chan<- string) {
		urls := []string{"https://httpbin.org/html", "https://httpbin.org/get"}
		for _, u := range urls {
			select {
			case out <- u:
			case <-ctx.Done():
				return
			}
		}
	}

	resultChan := orch.Run(ctx, produce)

	count := 0
	for r := range resultChan {
		count++
		t.Logf("URL: %s | Action: %s | Reason: %s | Err: %v", r.URL, r.Action, r.Reason, r.Err)
		if r.Err != nil {
			t.Errorf("unexpected error for %s: %v", r.URL, r.Err)
		}
	}

	if count != 2 {
		t.Fatalf("expected 2 results, got %d", count)
	}
}

func TestOrchestratorRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := client.NewClearnet()
	f := fetcher.New(c)
	l := ratelimiter.New(1, 1) // slow rate, forces work to still be pending

	msh := minhash.New(200)
	lshIdx := lsh.New(50, 2)
	bf := bloom.New(958058, 7)
	mock := store.NewMock()
	pipe := pipeline.New(msh, bf, mock, lshIdx)

	orch := New(f, l, pipe, 2, 5*1024*1024)

	produce := func(ctx context.Context, out chan<- string) {
		for i := 0; i < 20; i++ { // more URLs than will finish before cancel
			select {
			case out <- "https://httpbin.org/get":
			case <-ctx.Done():
				return
			}
		}
	}

	resultChan := orch.Run(ctx, produce)

	time.AfterFunc(200*time.Millisecond, cancel)

	count := 0
	for range resultChan {
		count++
	}

	t.Logf("processed %d results before cancellation took effect", count)
	if count >= 20 {
		t.Fatal("expected cancellation to stop processing before all 20 completed")
	}
}

func TestOrchestratorSkipsDuplicateURL(t *testing.T) {
	ctx := context.Background()
	c := client.NewClearnet()
	f := fetcher.New(c)
	l := ratelimiter.New(5, 5)

	msh := minhash.New(200)
	lshIdx := lsh.New(50, 2)
	bf := bloom.New(958058, 7)
	mock := store.NewMock()
	pipe := pipeline.New(msh, bf, mock, lshIdx)

	orch := New(f, l, pipe, 2, 5*1024*1024)

	produce := func(ctx context.Context, out chan<- string) {
		// same URL queued twice by an external producer
		urls := []string{
			"https://httpbin.org/html",
			"https://httpbin.org/html",
		}
		for _, u := range urls {
			select {
			case out <- u:
			case <-ctx.Done():
				return
			}
		}
	}

	resultChan := orch.Run(ctx, produce)

	var results []CrawlResults
	for r := range resultChan {
		results = append(results, r)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	passCount, skipCount := 0, 0
	for _, r := range results {
		t.Logf("URL: %s | Action: %s | Reason: %s", r.URL, r.Action, r.Reason)
		switch r.Action {
		case "pass", "drop":
			passCount++
		case "skip":
			skipCount++
		}
	}

	if passCount != 1 {
		t.Fatalf("expected exactly 1 actually-processed result, got %d", passCount)
	}
	if skipCount != 1 {
		t.Fatalf("expected exactly 1 skipped duplicate URL, got %d", skipCount)
	}
}

type MockFetcher struct {
	body []byte
}

func (m *MockFetcher) Fetch(ctx context.Context, url string) (*fetcher.Result, error) {
	return &fetcher.Result{
		URL:        url,
		Body:       m.body,
		StatusCode: 200,
	}, nil
}

func BenchmarkOrchestratorThroughput(b *testing.B) {
	ctx := context.Background()
	c := client.NewClearnet()
	f := fetcher.New(c)
	l := ratelimiter.New(50, 50) // high rate, isolate orchestrator overhead from rate limiting

	msh := minhash.New(200)
	lshIdx := lsh.New(50, 2)
	bf := bloom.New(958058, 7)
	mock := store.NewMock()
	pipe := pipeline.New(msh, bf, mock, lshIdx)

	orch := New(f, l, pipe, 10, 5*1024*1024) // 10 workers

	urls := make([]string, b.N)
	for i := range urls {
		urls[i] = "https://httpbin.org/html"
	}

	produce := func(ctx context.Context, out chan<- string) {
		for _, u := range urls {
			select {
			case out <- u:
			case <-ctx.Done():
				return
			}
		}
	}

	b.ResetTimer()
	resultChan := orch.Run(ctx, produce)
	count := 0
	for range resultChan {
		count++
	}
	b.StopTimer()

	b.ReportMetric(float64(count)/b.Elapsed().Seconds(), "docs/sec")
}

func BenchmarkPipelineThroughput(b *testing.B) {
	msh := minhash.New(200)
	lshIdx := lsh.New(50, 2)
	bf := bloom.New(9585058, 7)
	mock := store.NewMock()
	pipe := pipeline.New(msh, bf, mock, lshIdx)

	// pre-generate documents so generation isn't measured
	docs := make([]*pipeline.Document, b.N)
	for i := range docs {
		docs[i] = &pipeline.Document{
			Body:       fmt.Sprintf("ransomware campaign %d exploiting infrastructure via malicious payload", i),
			Indicators: []string{fmt.Sprintf("192.168.1.%d", i%254)},
		}
	}

	ctx := context.Background()
	b.ResetTimer() // start measuring here, after setup

	for i := 0; i < b.N; i++ {
		pipe.Process(ctx, docs[i])
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "docs/sec")
}
