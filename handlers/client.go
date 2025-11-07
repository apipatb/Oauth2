package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/apipatb/oauth2-system/database"
	"github.com/apipatb/oauth2-system/models"
)

// ClientHandler handles OAuth2 client management
type ClientHandler struct {
	db *database.Database
}

// NewClientHandler creates a new client handler
func NewClientHandler(db *database.Database) *ClientHandler {
	return &ClientHandler{db: db}
}

// CreateClientRequest represents a request to create a new OAuth2 client
type CreateClientRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// CreateClientResponse represents a response for created client
type CreateClientResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Message      string   `json:"message"`
}

// HandleCreateClient handles creating a new OAuth2 client
func (h *ClientHandler) HandleCreateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Name == "" {
		h.sendError(w, "Client name is required", http.StatusBadRequest)
		return
	}

	if len(req.RedirectURIs) == 0 {
		h.sendError(w, "At least one redirect URI is required", http.StatusBadRequest)
		return
	}

	// Generate client ID and secret
	clientID := "client_" + generateID()
	clientSecret := generateSecret()

	// Create client
	client := &models.Client{
		ID:           clientID,
		Secret:       clientSecret, // Will be hashed by database layer
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
	}

	if err := h.db.CreateClient(client); err != nil {
		h.sendError(w, "Failed to create client", http.StatusInternalServerError)
		return
	}

	response := CreateClientResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret, // Return plain text secret (only time it's shown)
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		Message:      "Client created successfully. Save the client secret - it won't be shown again!",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// HandleGetClient handles retrieving client information
func (h *ClientHandler) HandleGetClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		h.sendError(w, "client_id parameter required", http.StatusBadRequest)
		return
	}

	client, err := h.db.GetClient(clientID)
	if err != nil {
		h.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	if client == nil {
		h.sendError(w, "Client not found", http.StatusNotFound)
		return
	}

	// Don't return secret
	response := map[string]interface{}{
		"client_id":     client.ID,
		"name":          client.Name,
		"redirect_uris": client.RedirectURIs,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *ClientHandler) sendError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

func generateSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
