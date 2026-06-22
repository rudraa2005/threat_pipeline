package retry

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestRetrySucceedsAfterFailures(t *testing.T) {
	attempts := 0
	err := Do(context.Background(), Config{
		MaxAttempts: 4,
		BaseDelay:   1 * time.Millisecond,
		MaxDelay:    10 * time.Millisecond,
	}, func() (bool, error) {
		attempts++
		if attempts < 3 {
			return true, fmt.Errorf("simulated failure")
		}
		return true, nil
	})

	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetryOnNonRetryable(t *testing.T) {
	attempts := 0

	err := Do(context.Background(), DefaultConfig(), func() (bool, error) {
		attempts++
		return false, fmt.Errorf("404 not found")
	})

	if err == nil {
		t.Fatal("expected error")
	}

	if attempts != 1 {
		t.Fatalf("Expected only 1 attempt but got: %v attempts", attempts)
	}
}

func TestRetryOnExhaustibleAttempts(t *testing.T) {
	attempts := 0

	err := Do(context.Background(), Config{
		MaxAttempts: 3,
		BaseDelay:   1 * time.Millisecond,
		MaxDelay:    5 * time.Millisecond,
	}, func() (bool, error) {
		attempts++
		return true, fmt.Errorf("always fails")
	})

	if err == nil {
		t.Fatalf("expected error")
	}

	if attempts != 3 {
		t.Fatalf("expected 3 attempts got %v", attempts)
	}
}
