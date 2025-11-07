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

	"github.com/apipatb/oauth2-system/config"
	"github.com/apipatb/oauth2-system/database"
	"github.com/apipatb/oauth2-system/jwt"
	"github.com/apipatb/oauth2-system/models"
	"github.com/apipatb/oauth2-system/pkce"
)

// ServerV2 handles OAuth2 authorization server endpoints with JWT and database
type ServerV2 struct {
	db         *database.Database
	jwtManager *jwt.JWTManager
	config     *config.Config
}

// NewServerV2 creates a new OAuth2 authorization server v2
func NewServerV2(db *database.Database, jwtManager *jwt.JWTManager, cfg *config.Config) *ServerV2 {
	return &ServerV2{
		db:         db,
		jwtManager: jwtManager,
		config:     cfg,
	}
}

// HandleAuthorize handles the /oauth/authorize endpoint
func (s *ServerV2) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
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
func (s *ServerV2) showLoginPage(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	// Validate client
	client, err := s.db.GetClient(clientID)
	if err != nil || client == nil {
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

	// Validate PKCE if provided
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "plain"
		}
		if !pkce.ValidateChallengeMethod(codeChallengeMethod) {
			http.Error(w, "Invalid code_challenge_method", http.StatusBadRequest)
			return
		}
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
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .info { background: #e7f3ff; padding: 10px; border-radius: 3px; margin-bottom: 15px; }
        .pkce-badge { background: #48bb78; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Authorization Required</h2>
        <div class="info">
            <strong>{{.ClientName}}</strong> is requesting access to your account.
            <br><br>
            <strong>Scopes:</strong> {{.Scope}}
            {{if .PKCEEnabled}}
            <br><br>
            <span class="pkce-badge">🔒 PKCE Enabled</span>
            {{end}}
        </div>
        <form method="POST" action="/oauth/authorize">
            <input type="hidden" name="client_id" value="{{.ClientID}}">
            <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
            <input type="hidden" name="state" value="{{.State}}">
            <input type="hidden" name="scope" value="{{.Scope}}">
            <input type="hidden" name="response_type" value="code">
            <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
            <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">

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

	data := map[string]interface{}{
		"ClientID":            clientID,
		"ClientName":          client.Name,
		"RedirectURI":         redirectURI,
		"State":               state,
		"Scope":               scope,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
		"PKCEEnabled":         codeChallenge != "",
	}

	w.Header().Set("Content-Type", "text/html")
	t.Execute(w, data)
}

// processAuthorization processes the authorization form submission
func (s *ServerV2) processAuthorization(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	username := r.FormValue("username")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	scope := r.FormValue("scope")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	// Validate user credentials
	user, err := s.db.ValidateUserPassword(username, password)
	if err != nil || user == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Validate client
	client, err := s.db.GetClient(clientID)
	if err != nil || client == nil {
		http.Error(w, "Invalid client", http.StatusBadRequest)
		return
	}

	// Generate authorization code
	code := generateRandomString(32)
	authCode := &models.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              user.ID,
		RedirectURI:         redirectURI,
		ExpiresAt:           time.Now().Add(time.Duration(s.config.AuthCodeLifetime) * time.Second),
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	if err := s.db.SaveAuthorizationCode(authCode); err != nil {
		http.Error(w, "Failed to save authorization code", http.StatusInternalServerError)
		return
	}

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
func (s *ServerV2) HandleToken(w http.ResponseWriter, r *http.Request) {
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
func (s *ServerV2) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	// Validate client credentials
	valid, err := s.db.ValidateClient(clientID, clientSecret)
	if err != nil || !valid {
		s.sendError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Get and validate authorization code
	authCode, err := s.db.GetAuthorizationCode(code)
	if err != nil || authCode == nil {
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

	// Validate PKCE if code challenge was used
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			s.sendError(w, "invalid_grant", "code_verifier required", http.StatusBadRequest)
			return
		}

		if err := pkce.ValidateCodeVerifier(codeVerifier); err != nil {
			s.sendError(w, "invalid_grant", "Invalid code_verifier", http.StatusBadRequest)
			return
		}

		if !pkce.VerifyCodeChallenge(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			s.sendError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
			return
		}
	}

	// Generate JWT tokens
	s.issueTokens(w, clientID, authCode.UserID, authCode.Scope)
}

// handleRefreshTokenGrant handles refresh token grant type
func (s *ServerV2) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate client credentials
	valid, err := s.db.ValidateClient(clientID, clientSecret)
	if err != nil || !valid {
		s.sendError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Check if token is revoked
	revoked, err := s.db.IsTokenRevoked(refreshToken)
	if err != nil || revoked {
		s.sendError(w, "invalid_grant", "Token revoked or invalid", http.StatusBadRequest)
		return
	}

	// Validate refresh token
	claims, err := s.jwtManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		s.sendError(w, "invalid_grant", "Invalid refresh token", http.StatusBadRequest)
		return
	}

	// Validate client ID matches
	if claims.ClientID != clientID {
		s.sendError(w, "invalid_grant", "Client ID mismatch", http.StatusBadRequest)
		return
	}

	// Generate new tokens
	s.issueTokens(w, clientID, claims.UserID, claims.Scope)
}

// handleClientCredentialsGrant handles client credentials grant type
func (s *ServerV2) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	scope := r.FormValue("scope")

	// Validate client credentials
	valid, err := s.db.ValidateClient(clientID, clientSecret)
	if err != nil || !valid {
		s.sendError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Generate access token only (no refresh token for client credentials)
	accessToken, err := s.jwtManager.GenerateAccessToken(
		"", // No user ID for client credentials
		clientID,
		scope,
		time.Duration(s.config.AccessTokenLifetime)*time.Second,
	)

	if err != nil {
		s.sendError(w, "server_error", "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   s.config.AccessTokenLifetime,
		Scope:       scope,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// issueTokens generates and sends access and refresh tokens
func (s *ServerV2) issueTokens(w http.ResponseWriter, clientID, userID, scope string) {
	accessToken, err := s.jwtManager.GenerateAccessToken(
		userID,
		clientID,
		scope,
		time.Duration(s.config.AccessTokenLifetime)*time.Second,
	)
	if err != nil {
		s.sendError(w, "server_error", "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(
		userID,
		clientID,
		scope,
		time.Duration(s.config.RefreshTokenLifetime)*time.Second,
	)
	if err != nil {
		s.sendError(w, "server_error", "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	response := models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.config.AccessTokenLifetime,
		RefreshToken: refreshToken,
		Scope:        scope,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleRevoke handles token revocation
func (s *ServerV2) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate client credentials
	valid, err := s.db.ValidateClient(clientID, clientSecret)
	if err != nil || !valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if token == "" {
		http.Error(w, "Token required", http.StatusBadRequest)
		return
	}

	// Determine token type if not provided
	if tokenTypeHint == "" {
		// Try to validate as access token first
		if _, err := s.jwtManager.ValidateAccessToken(token); err == nil {
			tokenTypeHint = "access_token"
		} else if _, err := s.jwtManager.ValidateRefreshToken(token); err == nil {
			tokenTypeHint = "refresh_token"
		}
	}

	// Revoke token
	if err := s.db.RevokeToken(token, tokenTypeHint); err != nil {
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	// Return 200 OK (RFC 7009 says to return 200 even if token was invalid)
	w.WriteHeader(http.StatusOK)
}

// ValidateToken validates an access token from the Authorization header
func (s *ServerV2) ValidateToken(r *http.Request) (*jwt.TokenClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	token := parts[1]

	// Check if token is revoked
	revoked, err := s.db.IsTokenRevoked(token)
	if err != nil {
		return nil, fmt.Errorf("failed to check token status")
	}
	if revoked {
		return nil, fmt.Errorf("token has been revoked")
	}

	// Validate JWT
	claims, err := s.jwtManager.ValidateAccessToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token")
	}

	return claims, nil
}

// sendError sends an OAuth2 error response
func (s *ServerV2) sendError(w http.ResponseWriter, errorCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(models.ErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:length]
}
