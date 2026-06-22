package fetcher

import (
	"context"
	"net/http"
	"testing"
	"threat_pipeline/crawler/client"
	"time"
)

func TestFetcherClearnet(t *testing.T) {
	client := client.NewClearnet()
	f := New(client)

	result, err := f.Fetch("https://httpbin.org/get", context.Background())
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	if result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", result.StatusCode)
	}

	t.Logf("fetched %d bytes from %s: %v", len(result.Body), result.URL, string(result.Body))

}

func TestFetcherCancellation(t *testing.T) {
	client := client.NewClearnet()

	f := New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, err := f.Fetch("https://httpbin.org/get", ctx)
	if err == nil {
		t.Fatal("expected cancellation error, got nil")
	}
	t.Logf("got expected error : %v", err)
}

func TestFetcherTor(t *testing.T) {
	client, err := client.NewTor()
	if err != nil {
		t.Fatalf("could not create a client : %v", err)
	}

	f := New(client)
	result, err := f.Fetch("https://httpbin.org/get", context.Background())
	if err != nil {
		t.Fatalf("error fetching url: %v", err)
	}

	if result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %v", result.StatusCode)
	}

	t.Logf("fetched %d bytes through tor", len(result.Body))
}
