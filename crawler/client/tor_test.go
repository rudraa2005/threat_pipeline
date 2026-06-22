package client

import (
	"io"
	"strings"
	"testing"
)

func TestTorClient(t *testing.T) {
	client, err := NewTor()
	if err != nil {
		t.Fatalf("failed to create tor client: %v", err)
	}

	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		t.Fatalf("request failed:%v", err)
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	t.Logf("response: %v", body)

	if !strings.Contains(string(body), `"IsTor":true`) {
		t.Fatal("not routing through tor")
	}

}
