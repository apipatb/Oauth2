package models

import "time"

// Client represents an OAuth2 client application
type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
	Name         string
}

// AuthorizationCode represents a temporary authorization code
type AuthorizationCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	ExpiresAt           time.Time
	Scope               string
	CodeChallenge       string // PKCE code challenge
	CodeChallengeMethod string // PKCE code challenge method (plain or S256)
}

// AccessToken represents an OAuth2 access token
type AccessToken struct {
	Token     string
	ClientID  string
	UserID    string
	ExpiresAt time.Time
	Scope     string
}

// RefreshToken represents an OAuth2 refresh token
type RefreshToken struct {
	Token     string
	ClientID  string
	UserID    string
	ExpiresAt time.Time
	Scope     string
}

// User represents a simple user account
type User struct {
	ID       string
	Username string
	Password string // In production, this should be hashed
	Email    string
}

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ErrorResponse represents an OAuth2 error response
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}
