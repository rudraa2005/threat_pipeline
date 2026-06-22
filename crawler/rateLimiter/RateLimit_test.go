package ratelimiter

import (
	"context"
	"testing"
	"time"
)

func TestRateLimit(t *testing.T) {
	h1 := New(2, 5)

	ctx := context.Background()

	start := time.Now()

	for i := 0; i < 10; i++ {
		err := h1.Wait(ctx, "https://example.com/page")
		if err != nil {
			t.Fatalf("wait failed: %v", err)
		}
	}

	elapsed := time.Since(start)
	t.Logf("10 requests took %v", elapsed)

	if elapsed < 1900*time.Millisecond {
		t.Fatalf("rate limiting not enforced, elapsed too short: %v", elapsed)
	}
}

func TestRateLimitIsolation(t *testing.T) {
	h1 := New(1, 1)
	ctx := context.Background()
	start := time.Now()
	err1 := h1.Wait(ctx, "https://example.com/page")
	err2 := h1.Wait(ctx, "https://different-host.com/page")

	if err1 != nil || err2 != nil {
		t.Fatalf("error encountered: %v,%v", err1, err2)
	}

	elapsed := time.Since(start)
	t.Logf("2 requests took %v", elapsed)

	if elapsed > 100*time.Millisecond {
		t.Fatalf("diff hosts should not block each other,took: %v", elapsed)
	}
}
