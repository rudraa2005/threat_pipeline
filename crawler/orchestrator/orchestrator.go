package orchestrator

import (
	"context"
	"log"
	"sync"
	"threat_pipeline/crawler/entities"
	"threat_pipeline/crawler/extractor"
	"threat_pipeline/crawler/fetcher"
	ratelimiter "threat_pipeline/crawler/rateLimiter"
	"threat_pipeline/crawler/retry"
	"threat_pipeline/data_ingestion/bloom"
	"threat_pipeline/data_ingestion/pipeline"
	"time"
)

type Orchestrator struct {
	Fetcher  *fetcher.Fetcher
	Limiter  *ratelimiter.HostLimiter
	Pipeline *pipeline.Pipeline
	workers  int
	maxBytes int
	urlSeen  *bloom.BloomFilter
}

func New(fetcher *fetcher.Fetcher, limiter *ratelimiter.HostLimiter, pipeline *pipeline.Pipeline, workers int, maxBytes int) *Orchestrator {
	return &Orchestrator{
		Fetcher:  fetcher,
		Limiter:  limiter,
		Pipeline: pipeline,
		workers:  workers,
		urlSeen:  bloom.New(958058, 7),
		maxBytes: maxBytes,
	}
}

type CrawlResults struct {
	URL    string
	Action string
	Reason string
	Err    error
}

func (o *Orchestrator) Run(ctx context.Context, produce func(ctx context.Context, out chan<- string)) <-chan CrawlResults {
	urlChan := make(chan string, o.workers*2)
	resultChan := make(chan CrawlResults, o.workers*2)

	go func() {
		defer close(urlChan)
		produce(ctx, urlChan)
	}()

	var wg sync.WaitGroup

	for w := 0; w < o.workers; w++ {
		wg.Add(1)
		go o.worker(ctx, &wg, urlChan, resultChan)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	return resultChan
}

func (o *Orchestrator) worker(ctx context.Context, wg *sync.WaitGroup, urls <-chan string, results chan<- CrawlResults) {
	defer wg.Done()
	for {
		select {
		case url, ok := <-urls:
			if !ok {
				return
			}
			results <- o.processOne(ctx, url)
		case <-ctx.Done():
			return
		}
	}
}

func (o *Orchestrator) processOne(ctx context.Context, url string) CrawlResults {
	if o.urlSeen.TestAndAdd([]byte(url)) {
		return CrawlResults{URL: url, Action: "skip", Reason: "seen before"}
	}
	if err := o.Limiter.Wait(ctx, url); err != nil {
		return CrawlResults{URL: url, Err: err}
	}

	var body []byte
	err := retry.Do(ctx, retry.DefaultConfig(), func() (bool, error) {
		res, err := o.Fetcher.Fetch(url, ctx)
		if err != nil {
			return true, err
		}
		body = res.Body
		return false, nil
	})
	if err != nil {
		return CrawlResults{URL: url, Err: err}
	}

	text, err := extractor.ExtractText(body, o.maxBytes)
	if err != nil {
		return CrawlResults{URL: url, Err: err}
	}

	indicators := entities.Extract(text)
	doc := &pipeline.Document{Body: text, Indicators: indicators.Flatten()}

	start := time.Now()
	res := o.Pipeline.Process(ctx, doc)

	log.Printf("[%s][%s][%s] in %v", url, res.Action, res.Reason, time.Since(start))

	return CrawlResults{URL: url, Action: res.Action, Reason: res.Reason}
}
