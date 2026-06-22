package retry

import (
	"context"
	"math"
	"math/rand"
	"time"
)

type Config struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

func DefaultConfig() Config {
	return Config{
		MaxAttempts: 4,
		BaseDelay:   1 * time.Second,
		MaxDelay:    30 * time.Second,
	}
}

func Do(ctx context.Context, cfg Config, fn func() (retryable bool, err error)) error {
	var lastError error

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		retryable, err := fn()
		if err == nil {
			return nil
		}
		lastError = err

		if !retryable {
			return err
		}

		if attempt == cfg.MaxAttempts-1 {
			break
		}

		delay := backOffDelay(cfg, attempt)

		select {
		case <-time.After(delay):

		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return lastError
}

func backOffDelay(cfg Config, attempt int) time.Duration {
	exp := float64(cfg.BaseDelay) * math.Pow(2, float64(attempt))

	if exp > float64(cfg.MaxDelay) {
		exp = float64(cfg.MaxDelay)
	}

	jittered := rand.Float64() * exp

	return time.Duration(jittered)
}
