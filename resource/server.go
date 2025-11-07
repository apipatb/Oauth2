package resource

import (
	"encoding/json"
	"net/http"

	"github.com/apipatb/oauth2-system/auth"
)

// Server handles protected resource endpoints
type Server struct {
	authServer *auth.Server
}

// NewServer creates a new resource server
func NewServer(authServer *auth.Server) *Server {
	return &Server{
		authServer: authServer,
	}
}

// HandleUserInfo handles the /api/userinfo endpoint
func (s *Server) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Validate access token
	token, err := s.authServer.ValidateToken(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"API\"")
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Return user information
	response := map[string]interface{}{
		"user_id": token.UserID,
		"scope":   token.Scope,
		"message": "Successfully accessed protected resource",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleProtectedData handles the /api/data endpoint
func (s *Server) HandleProtectedData(w http.ResponseWriter, r *http.Request) {
	// Validate access token
	token, err := s.authServer.ValidateToken(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"API\"")
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Return some protected data
	response := map[string]interface{}{
		"user_id": token.UserID,
		"data": []map[string]string{
			{"id": "1", "title": "Protected Item 1", "description": "This is protected data"},
			{"id": "2", "title": "Protected Item 2", "description": "Only accessible with valid token"},
			{"id": "3", "title": "Protected Item 3", "description": "OAuth2 secured resource"},
		},
		"timestamp": "2025-11-07T12:00:00Z",
		"scope":     token.Scope,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandlePublicEndpoint handles a public endpoint that doesn't require authentication
func (s *Server) HandlePublicEndpoint(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "This is a public endpoint, no authentication required",
		"status":  "ok",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
