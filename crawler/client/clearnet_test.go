package client

import (
	"testing"
	"time"
)

func TestClient(t *testing.T) {
	url := "https://httpbin.org/get"
	client := NewClearnet()

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("URL could not be resolved, %s", url)
	}

	t.Logf("200 for %s", resp.Status)

}

func TestClientWithTimeout(t *testing.T) {
	url := "https://httpbin.org/get"
	client := NewClearnetWithTimeout(1 * time.Millisecond)

	_, err := client.Get(url)
	if err == nil {
		t.Fatalf("timeout expected, got nil")
	}

	t.Logf("Got expected timeout %v", err)
}
