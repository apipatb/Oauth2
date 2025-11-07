package resource

import (
	"encoding/json"
	"net/http"

	"github.com/apipatb/oauth2-system/auth"
)

// ServerV2 handles protected resource endpoints with JWT validation
type ServerV2 struct {
	authServer *auth.ServerV2
}

// NewServerV2 creates a new resource server v2
func NewServerV2(authServer *auth.ServerV2) *ServerV2 {
	return &ServerV2{
		authServer: authServer,
	}
}

// HandleUserInfo handles the /api/userinfo endpoint
func (s *ServerV2) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Validate access token
	claims, err := s.authServer.ValidateToken(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"API\"")
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Return user information from JWT claims
	response := map[string]interface{}{
		"user_id":   claims.UserID,
		"client_id": claims.ClientID,
		"scope":     claims.Scope,
		"issued_at": claims.IssuedAt.Time.Unix(),
		"expires_at": claims.ExpiresAt.Time.Unix(),
		"message":   "Successfully accessed protected resource",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleProtectedData handles the /api/data endpoint
func (s *ServerV2) HandleProtectedData(w http.ResponseWriter, r *http.Request) {
	// Validate access token
	claims, err := s.authServer.ValidateToken(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"API\"")
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Return some protected data
	response := map[string]interface{}{
		"user_id":   claims.UserID,
		"client_id": claims.ClientID,
		"data": []map[string]string{
			{"id": "1", "title": "Protected Item 1", "description": "This is protected data"},
			{"id": "2", "title": "Protected Item 2", "description": "Only accessible with valid JWT token"},
			{"id": "3", "title": "Protected Item 3", "description": "OAuth2 + JWT secured resource"},
		},
		"scope": claims.Scope,
		"token_info": map[string]interface{}{
			"issued_at":  claims.IssuedAt.Time.Unix(),
			"expires_at": claims.ExpiresAt.Time.Unix(),
			"issuer":     claims.Issuer,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandlePublicEndpoint handles a public endpoint that doesn't require authentication
func (s *ServerV2) HandlePublicEndpoint(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "This is a public endpoint, no authentication required",
		"status":  "ok",
		"version": "2.0",
		"features": []string{
			"JWT tokens",
			"Database storage",
			"PKCE support",
			"Token revocation",
			"Rate limiting",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
