package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/apipatb/oauth2-system/database"
	"github.com/apipatb/oauth2-system/models"
)

// UserHandler handles user management endpoints
type UserHandler struct {
	db *database.Database
}

// NewUserHandler creates a new user handler
func NewUserHandler(db *database.Database) *UserHandler {
	return &UserHandler{db: db}
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// RegisterResponse represents a user registration response
type RegisterResponse struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

// HandleRegister handles user registration
func (h *UserHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Username == "" || req.Password == "" || req.Email == "" {
		h.sendError(w, "Username, password, and email are required", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	existingUser, err := h.db.GetUserByUsername(req.Username)
	if err != nil {
		h.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}
	if existingUser != nil {
		h.sendError(w, "Username already exists", http.StatusConflict)
		return
	}

	// Create user
	userID := generateID()
	user := &models.User{
		ID:       userID,
		Username: req.Username,
		Password: req.Password, // Will be hashed by database layer
		Email:    req.Email,
	}

	if err := h.db.CreateUser(user); err != nil {
		h.sendError(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	response := RegisterResponse{
		UserID:  userID,
		Message: "User registered successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// HandleGetUser handles getting user information
func (h *UserHandler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		h.sendError(w, "Username parameter required", http.StatusBadRequest)
		return
	}

	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		h.sendError(w, "Database error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		h.sendError(w, "User not found", http.StatusNotFound)
		return
	}

	// Don't return password
	response := map[string]interface{}{
		"user_id":  user.ID,
		"username": user.Username,
		"email":    user.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *UserHandler) sendError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:16]
}
