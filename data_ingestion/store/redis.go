package store

import (
	"context"
	"sync"

	"github.com/redis/go-redis/v9"
)

// Storage defines the contract both Redis and Mock must satisfy
type Storage interface {
	Exists(ctx context.Context, hash string) (bool, error)
	Add(ctx context.Context, hash string) error
}

// -----------------------------------------------------------------
// PRODUCTION IMPLEMENTATION (Redis)
// -----------------------------------------------------------------

type HashStore struct {
	client *redis.Client
	setKey string
}

// New instantiates the live production Redis backed engine
func New(addr, setKey string) *HashStore {
	return &HashStore{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			PoolSize: 10, // Reuses connections under concurrent pressure
		}),
		setKey: setKey,
	}
}

func (s *HashStore) Exists(ctx context.Context, hash string) (bool, error) {
	return s.client.SIsMember(ctx, s.setKey, hash).Result()
}

func (s *HashStore) Add(ctx context.Context, hash string) error {
	return s.client.SAdd(ctx, s.setKey, hash).Err()
}

// -----------------------------------------------------------------
// TESTING IMPLEMENTATION (In-Memory Mock)
// -----------------------------------------------------------------

type MockHashStore struct {
	mu sync.RWMutex
	db map[string]bool
}

// NewMock returns a Storage interface wrapped around an in-memory map
func NewMock() Storage {
	return &MockHashStore{
		db: make(map[string]bool),
	}
}

func (m *MockHashStore) Exists(ctx context.Context, hash string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.db[hash], nil
}

func (m *MockHashStore) Add(ctx context.Context, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db[hash] = true
	return nil
}
