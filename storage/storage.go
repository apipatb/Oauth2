package storage

import (
	"sync"
	"time"

	"github.com/apipatb/oauth2-system/models"
)

// Storage provides in-memory storage for OAuth2 data
type Storage struct {
	clients           map[string]*models.Client
	users             map[string]*models.User
	authCodes         map[string]*models.AuthorizationCode
	accessTokens      map[string]*models.AccessToken
	refreshTokens     map[string]*models.RefreshToken
	mu                sync.RWMutex
}

// NewStorage creates a new storage instance with demo data
func NewStorage() *Storage {
	s := &Storage{
		clients:       make(map[string]*models.Client),
		users:         make(map[string]*models.User),
		authCodes:     make(map[string]*models.AuthorizationCode),
		accessTokens:  make(map[string]*models.AccessToken),
		refreshTokens: make(map[string]*models.RefreshToken),
	}

	// Add demo client
	s.clients["demo-client-id"] = &models.Client{
		ID:     "demo-client-id",
		Secret: "demo-client-secret",
		RedirectURIs: []string{
			"http://localhost:8080/callback",
			"http://localhost:8080/oauth/callback",
		},
		Name: "Demo Client Application",
	}

	// Add demo user
	s.users["user1"] = &models.User{
		ID:       "user1",
		Username: "demo",
		Password: "password", // In production, use bcrypt
		Email:    "demo@example.com",
	}

	return s
}

// GetClient retrieves a client by ID
func (s *Storage) GetClient(clientID string) (*models.Client, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, exists := s.clients[clientID]
	return client, exists
}

// ValidateClient checks if client credentials are valid
func (s *Storage) ValidateClient(clientID, clientSecret string) bool {
	client, exists := s.GetClient(clientID)
	if !exists {
		return false
	}
	return client.Secret == clientSecret
}

// GetUser retrieves a user by username
func (s *Storage) GetUser(username string) (*models.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, exists := s.users[username]
	return user, exists
}

// ValidateUser checks if user credentials are valid
func (s *Storage) ValidateUser(username, password string) (*models.User, bool) {
	user, exists := s.GetUser(username)
	if !exists {
		return nil, false
	}
	if user.Password != password {
		return nil, false
	}
	return user, true
}

// SaveAuthCode stores an authorization code
func (s *Storage) SaveAuthCode(code *models.AuthorizationCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[code.Code] = code
}

// GetAuthCode retrieves and deletes an authorization code
func (s *Storage) GetAuthCode(code string) (*models.AuthorizationCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	authCode, exists := s.authCodes[code]
	if !exists {
		return nil, false
	}
	// Check if expired
	if time.Now().After(authCode.ExpiresAt) {
		delete(s.authCodes, code)
		return nil, false
	}
	// Delete after use (authorization code is single-use)
	delete(s.authCodes, code)
	return authCode, true
}

// SaveAccessToken stores an access token
func (s *Storage) SaveAccessToken(token *models.AccessToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[token.Token] = token
}

// GetAccessToken retrieves an access token
func (s *Storage) GetAccessToken(token string) (*models.AccessToken, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	accessToken, exists := s.accessTokens[token]
	if !exists {
		return nil, false
	}
	// Check if expired
	if time.Now().After(accessToken.ExpiresAt) {
		return nil, false
	}
	return accessToken, true
}

// SaveRefreshToken stores a refresh token
func (s *Storage) SaveRefreshToken(token *models.RefreshToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token.Token] = token
}

// GetRefreshToken retrieves a refresh token
func (s *Storage) GetRefreshToken(token string) (*models.RefreshToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refreshToken, exists := s.refreshTokens[token]
	if !exists {
		return nil, false
	}
	// Check if expired
	if time.Now().After(refreshToken.ExpiresAt) {
		delete(s.refreshTokens, token)
		return nil, false
	}
	// Delete after use (refresh token is single-use, will get a new one)
	delete(s.refreshTokens, token)
	return refreshToken, true
}

// CleanupExpired removes expired tokens (should be called periodically)
func (s *Storage) CleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Clean auth codes
	for code, authCode := range s.authCodes {
		if now.After(authCode.ExpiresAt) {
			delete(s.authCodes, code)
		}
	}

	// Clean access tokens
	for token, accessToken := range s.accessTokens {
		if now.After(accessToken.ExpiresAt) {
			delete(s.accessTokens, token)
		}
	}

	// Clean refresh tokens
	for token, refreshToken := range s.refreshTokens {
		if now.After(refreshToken.ExpiresAt) {
			delete(s.refreshTokens, token)
		}
	}
}
