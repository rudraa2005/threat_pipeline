package ratelimiter

import (
	"context"
	"net/url"
	"sync"

	"golang.org/x/time/rate"
)

type HostLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	burst    int
	rps      rate.Limit
}

func New(rps float64, burst int) *HostLimiter {
	return &HostLimiter{
		limiters: make(map[string]*rate.Limiter),
		burst:    burst,
		rps:      rate.Limit(rps),
	}
}

func (h *HostLimiter) GetLimiter(host string) *rate.Limiter {
	h.mu.Lock()
	defer h.mu.Unlock()

	l, exists := h.limiters[host]
	if !exists {
		l = rate.NewLimiter(h.rps, h.burst)
		h.limiters[host] = l
	}

	return l
}

func (h *HostLimiter) Wait(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	l := h.GetLimiter(u.Host)
	return l.Wait(ctx)
}
