package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/apipatb/oauth2-system/models"
	"github.com/apipatb/oauth2-system/storage"
)

// Server handles OAuth2 authorization server endpoints
type Server struct {
	storage *storage.Storage
}

// NewServer creates a new OAuth2 authorization server
func NewServer(store *storage.Storage) *Server {
	return &Server{
		storage: store,
	}
}

// HandleAuthorize handles the /oauth/authorize endpoint
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.showLoginPage(w, r)
		return
	}

	if r.Method == http.MethodPost {
		s.processAuthorization(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// showLoginPage displays the login and authorization page
func (s *Server) showLoginPage(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")

	// Validate client
	client, exists := s.storage.GetClient(clientID)
	if !exists {
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}

	// Validate redirect URI
	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>OAuth2 Authorization</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .container { border: 1px solid #ddd; padding: 20px; border-radius: 5px; background: #f9f9f9; }
        h2 { color: #333; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .info { background: #e7f3ff; padding: 10px; border-radius: 3px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Authorization Required</h2>
        <div class="info">
            <strong>{{.ClientName}}</strong> is requesting access to your account.
            <br><br>
            <strong>Scopes:</strong> {{.Scope}}
        </div>
        <form method="POST" action="/oauth/authorize">
            <input type="hidden" name="client_id" value="{{.ClientID}}">
            <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
            <input type="hidden" name="state" value="{{.State}}">
            <input type="hidden" name="scope" value="{{.Scope}}">
            <input type="hidden" name="response_type" value="code">

            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required value="demo">
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required value="password">
            </div>
            <button type="submit">Authorize</button>
        </form>
        <p style="text-align: center; margin-top: 15px; font-size: 12px; color: #666;">
            Demo credentials: username: <code>demo</code>, password: <code>password</code>
        </p>
    </div>
</body>
</html>`

	t, err := template.New("login").Parse(tmpl)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	data := map[string]string{
		"ClientID":    clientID,
		"ClientName":  client.Name,
		"RedirectURI": redirectURI,
		"State":       state,
		"Scope":       scope,
	}

	w.Header().Set("Content-Type", "text/html")
	t.Execute(w, data)
}

// processAuthorization processes the authorization form submission
func (s *Server) processAuthorization(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	username := r.FormValue("username")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	scope := r.FormValue("scope")

	// Validate user credentials
	user, valid := s.storage.ValidateUser(username, password)
	if !valid {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Validate client
	_, exists := s.storage.GetClient(clientID)
	if !exists {
		http.Error(w, "Invalid client", http.StatusBadRequest)
		return
	}

	// Generate authorization code
	code := generateRandomString(32)
	authCode := &models.AuthorizationCode{
		Code:        code,
		ClientID:    clientID,
		UserID:      user.ID,
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Scope:       scope,
	}

	s.storage.SaveAuthCode(authCode)

	// Redirect back to client with authorization code
	redirectURL, _ := url.Parse(redirectURI)
	query := redirectURL.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// HandleToken handles the /oauth/token endpoint
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, "invalid_request", "Only POST method allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r)
	case "client_credentials":
		s.handleClientCredentialsGrant(w, r)
	default:
		s.sendError(w, "unsupported_grant_type", "Grant type not supported", http.StatusBadRequest)
	}
}

// handleAuthorizationCodeGrant handles authorization code grant type
func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")

	// Validate client credentials
	if !s.storage.ValidateClient(clientID, clientSecret) {
		s.sendError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Get and validate authorization code
	authCode, exists := s.storage.GetAuthCode(code)
	if !exists {
		s.sendError(w, "invalid_grant", "Invalid or expired authorization code", http.StatusBadRequest)
		return
	}

	// Validate redirect URI matches
	if authCode.RedirectURI != redirectURI {
		s.sendError(w, "invalid_grant", "Redirect URI mismatch", http.StatusBadRequest)
		return
	}

	// Validate client ID matches
	if authCode.ClientID != clientID {
		s.sendError(w, "invalid_grant", "Client ID mismatch", http.StatusBadRequest)
		return
	}

	// Generate access token and refresh token
	s.issueTokens(w, clientID, authCode.UserID, authCode.Scope)
}

// handleRefreshTokenGrant handles refresh token grant type
func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate client credentials
	if !s.storage.ValidateClient(clientID, clientSecret) {
		s.sendError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Get and validate refresh token
	token, exists := s.storage.GetRefreshToken(refreshToken)
	if !exists {
		s.sendError(w, "invalid_grant", "Invalid or expired refresh token", http.StatusBadRequest)
		return
	}

	// Validate client ID matches
	if token.ClientID != clientID {
		s.sendError(w, "invalid_grant", "Client ID mismatch", http.StatusBadRequest)
		return
	}

	// Generate new access token and refresh token
	s.issueTokens(w, clientID, token.UserID, token.Scope)
}

// handleClientCredentialsGrant handles client credentials grant type
func (s *Server) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	scope := r.FormValue("scope")

	// Validate client credentials
	if !s.storage.ValidateClient(clientID, clientSecret) {
		s.sendError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Generate access token (no refresh token for client credentials)
	accessToken := generateRandomString(32)
	token := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    "", // No user for client credentials
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Scope:     scope,
	}

	s.storage.SaveAccessToken(token)

	response := models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       scope,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// issueTokens generates and sends access and refresh tokens
func (s *Server) issueTokens(w http.ResponseWriter, clientID, userID, scope string) {
	accessToken := generateRandomString(32)
	refreshToken := generateRandomString(32)

	// Save access token
	token := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Scope:     scope,
	}
	s.storage.SaveAccessToken(token)

	// Save refresh token
	refresh := &models.RefreshToken{
		Token:     refreshToken,
		ClientID:  clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour * 30), // 30 days
		Scope:     scope,
	}
	s.storage.SaveRefreshToken(refresh)

	response := models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        scope,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// sendError sends an OAuth2 error response
func (s *Server) sendError(w http.ResponseWriter, errorCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(models.ErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}

// ValidateToken validates an access token from the Authorization header
func (s *Server) ValidateToken(r *http.Request) (*models.AccessToken, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	token, exists := s.storage.GetAccessToken(parts[1])
	if !exists {
		return nil, fmt.Errorf("invalid or expired token")
	}

	return token, nil
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:length]
}
