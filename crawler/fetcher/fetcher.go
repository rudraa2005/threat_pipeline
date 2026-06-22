package fetcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Fetcher struct {
	client *http.Client
}

type Result struct {
	URL        string
	Body       []byte
	StatusCode int
	FetchedAt  time.Time
}

func New(client *http.Client) *Fetcher {
	return &Fetcher{
		client: client,
	}
}

func (f *Fetcher) Fetch(url string, ctx context.Context) (*Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; research-crawler/1.0)")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status:%v", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading body: %v", err)
	}

	return &Result{
		Body:       body,
		URL:        url,
		StatusCode: resp.StatusCode,
		FetchedAt:  time.Now(),
	}, nil
}
