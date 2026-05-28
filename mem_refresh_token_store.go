package fsa

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemRefreshTokenStore is an in-memory IRefreshTokenStore suitable for tests
// and single-process deployments. State is lost on restart, so users will
// have to log in again. For multi-replica or persistent setups, plug in a
// Redis- or database-backed implementation.
type MemRefreshTokenStore struct {
	mu      sync.Mutex
	entries map[string]memRTEntry
}

type memRTEntry struct {
	userID    uuid.UUID
	expiresAt time.Time
	used      bool
}

func NewMemRefreshTokenStore() *MemRefreshTokenStore {
	return &MemRefreshTokenStore{
		entries: make(map[string]memRTEntry),
	}
}

func (s *MemRefreshTokenStore) MarkIssued(_ context.Context, jti string, userID uuid.UUID, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepExpiredLocked()

	s.entries[jti] = memRTEntry{
		userID:    userID,
		expiresAt: expiresAt,
		used:      false,
	}
	return nil
}

func (s *MemRefreshTokenStore) MarkUsed(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[jti]
	if !ok {
		// Unknown jti: either never issued, or already swept after expiry.
		// In both cases the caller must not honour this token.
		return true, nil
	}
	if entry.used {
		return true, nil
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.entries, jti)
		return true, nil
	}
	entry.used = true
	s.entries[jti] = entry
	return false, nil
}

// sweepExpiredLocked removes expired entries. Caller must hold s.mu.
func (s *MemRefreshTokenStore) sweepExpiredLocked() {
	now := time.Now()
	for jti, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, jti)
		}
	}
}
