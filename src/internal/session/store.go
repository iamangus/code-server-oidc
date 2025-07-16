package session

import (
	"context"
	"sync"
	"time"
)

type SessionData struct {
	Username     string
	Email        string
	Token        string
	RefreshToken string
	ExpiresAt    time.Time
	LastActivity time.Time
}

type UserData struct {
	Username     string
	Port         int
	PID          int
	LastActivity time.Time
}

type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionData
	users    map[string]*UserData
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*SessionData),
		users:    make(map[string]*UserData),
	}
}

func (s *MemoryStore) SetSession(sessionID string, data *SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data.LastActivity = time.Now()
	s.sessions[sessionID] = data
}

func (s *MemoryStore) GetSession(sessionID string) (*SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	data, exists := s.sessions[sessionID]
	if !exists {
		return nil, false
	}
	
	if time.Now().After(data.ExpiresAt) {
		delete(s.sessions, sessionID)
		return nil, false
	}
	
	data.LastActivity = time.Now()
	return data, true
}

func (s *MemoryStore) DeleteSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

func (s *MemoryStore) SetUser(username string, data *UserData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data.LastActivity = time.Now()
	s.users[username] = data
}

func (s *MemoryStore) GetUser(username string) (*UserData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	data, exists := s.users[username]
	if !exists {
		return nil, false
	}
	
	return data, true
}

func (s *MemoryStore) DeleteUser(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, username)
}

func (s *MemoryStore) GetAllUsers() map[string]*UserData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	users := make(map[string]*UserData)
	for k, v := range s.users {
		users[k] = v
	}
	return users
}

func (s *MemoryStore) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *MemoryStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	
	// Clean expired sessions
	for sessionID, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, sessionID)
		}
	}
	
	// Clean inactive users (1 hour timeout)
	timeout := now.Add(-1 * time.Hour)
	for username, user := range s.users {
		if user.LastActivity.Before(timeout) {
			delete(s.users, username)
		}
	}
}