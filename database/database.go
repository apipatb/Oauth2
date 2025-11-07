package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"github.com/apipatb/oauth2-system/models"
)

// Database provides database operations
type Database struct {
	db *sql.DB
}

// NewDatabase creates a new database connection
func NewDatabase(dbType, connectionString string) (*Database, error) {
	var db *sql.DB
	var err error

	switch dbType {
	case "sqlite":
		db, err = sql.Open("sqlite3", connectionString)
	case "postgres":
		db, err = sql.Open("postgres", connectionString)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	if err != nil {
		return nil, err
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	database := &Database{db: db}

	// Initialize schema
	if err := database.initSchema(); err != nil {
		return nil, err
	}

	// Seed demo data
	if err := database.seedDemoData(); err != nil {
		return nil, err
	}

	return database, nil
}

// initSchema creates database tables
func (d *Database) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS clients (
		id TEXT PRIMARY KEY,
		secret TEXT NOT NULL,
		name TEXT NOT NULL,
		redirect_uris TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS authorization_codes (
		code TEXT PRIMARY KEY,
		client_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		redirect_uri TEXT NOT NULL,
		scope TEXT,
		code_challenge TEXT,
		code_challenge_method TEXT,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (client_id) REFERENCES clients(id),
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS revoked_tokens (
		token TEXT PRIMARY KEY,
		token_type TEXT NOT NULL,
		revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at);
	CREATE INDEX IF NOT EXISTS idx_revoked_tokens_token ON revoked_tokens(token);
	`

	_, err := d.db.Exec(schema)
	return err
}

// seedDemoData adds demo users and clients if they don't exist
func (d *Database) seedDemoData() error {
	// Check if demo user exists
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "demo").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		// Hash demo password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		// Insert demo user
		_, err = d.db.Exec(`
			INSERT INTO users (id, username, password, email)
			VALUES (?, ?, ?, ?)
		`, "user1", "demo", string(hashedPassword), "demo@example.com")
		if err != nil {
			return err
		}
	}

	// Check if demo client exists
	err = d.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", "demo-client-id").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		// Hash client secret
		hashedSecret, err := bcrypt.GenerateFromPassword([]byte("demo-client-secret"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		// Insert demo client
		_, err = d.db.Exec(`
			INSERT INTO clients (id, secret, name, redirect_uris)
			VALUES (?, ?, ?, ?)
		`, "demo-client-id", string(hashedSecret), "Demo Client Application", "http://localhost:8080/callback,http://localhost:8080/oauth/callback")
		if err != nil {
			return err
		}
	}

	return nil
}

// User operations

// GetUserByUsername retrieves a user by username
func (d *Database) GetUserByUsername(username string) (*models.User, error) {
	user := &models.User{}
	err := d.db.QueryRow(`
		SELECT id, username, password, email FROM users WHERE username = ?
	`, username).Scan(&user.ID, &user.Username, &user.Password, &user.Email)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetUserByID retrieves a user by ID
func (d *Database) GetUserByID(id string) (*models.User, error) {
	user := &models.User{}
	err := d.db.QueryRow(`
		SELECT id, username, password, email FROM users WHERE id = ?
	`, id).Scan(&user.ID, &user.Username, &user.Password, &user.Email)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

// CreateUser creates a new user
func (d *Database) CreateUser(user *models.User) error {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = d.db.Exec(`
		INSERT INTO users (id, username, password, email)
		VALUES (?, ?, ?, ?)
	`, user.ID, user.Username, string(hashedPassword), user.Email)

	return err
}

// ValidateUserPassword validates user credentials
func (d *Database) ValidateUserPassword(username, password string) (*models.User, error) {
	user, err := d.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	// Compare password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, nil
	}

	return user, nil
}

// Client operations

// GetClient retrieves a client by ID
func (d *Database) GetClient(clientID string) (*models.Client, error) {
	client := &models.Client{}
	var redirectURIs string

	err := d.db.QueryRow(`
		SELECT id, secret, name, redirect_uris FROM clients WHERE id = ?
	`, clientID).Scan(&client.ID, &client.Secret, &client.Name, &redirectURIs)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Parse redirect URIs
	client.RedirectURIs = parseRedirectURIs(redirectURIs)

	return client, nil
}

// ValidateClient validates client credentials
func (d *Database) ValidateClient(clientID, clientSecret string) (bool, error) {
	client, err := d.GetClient(clientID)
	if err != nil {
		return false, err
	}
	if client == nil {
		return false, nil
	}

	// Compare client secret
	err = bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(clientSecret))
	if err != nil {
		return false, nil
	}

	return true, nil
}

// CreateClient creates a new OAuth2 client
func (d *Database) CreateClient(client *models.Client) error {
	// Hash client secret
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(client.Secret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Join redirect URIs
	redirectURIs := joinRedirectURIs(client.RedirectURIs)

	_, err = d.db.Exec(`
		INSERT INTO clients (id, secret, name, redirect_uris)
		VALUES (?, ?, ?, ?)
	`, client.ID, string(hashedSecret), client.Name, redirectURIs)

	return err
}

// Authorization code operations

// SaveAuthorizationCode stores an authorization code
func (d *Database) SaveAuthorizationCode(code *models.AuthorizationCode) error {
	_, err := d.db.Exec(`
		INSERT INTO authorization_codes
		(code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, code.Code, code.ClientID, code.UserID, code.RedirectURI, code.Scope,
		code.CodeChallenge, code.CodeChallengeMethod, code.ExpiresAt)

	return err
}

// GetAuthorizationCode retrieves and deletes an authorization code
func (d *Database) GetAuthorizationCode(code string) (*models.AuthorizationCode, error) {
	authCode := &models.AuthorizationCode{}

	err := d.db.QueryRow(`
		SELECT code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at
		FROM authorization_codes WHERE code = ?
	`, code).Scan(&authCode.Code, &authCode.ClientID, &authCode.UserID, &authCode.RedirectURI,
		&authCode.Scope, &authCode.CodeChallenge, &authCode.CodeChallengeMethod, &authCode.ExpiresAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Check if expired
	if time.Now().After(authCode.ExpiresAt) {
		d.DeleteAuthorizationCode(code)
		return nil, nil
	}

	// Delete after retrieval (single-use)
	d.DeleteAuthorizationCode(code)

	return authCode, nil
}

// DeleteAuthorizationCode deletes an authorization code
func (d *Database) DeleteAuthorizationCode(code string) error {
	_, err := d.db.Exec("DELETE FROM authorization_codes WHERE code = ?", code)
	return err
}

// Token revocation

// RevokeToken marks a token as revoked
func (d *Database) RevokeToken(token, tokenType string) error {
	_, err := d.db.Exec(`
		INSERT INTO revoked_tokens (token, token_type) VALUES (?, ?)
	`, token, tokenType)
	return err
}

// IsTokenRevoked checks if a token is revoked
func (d *Database) IsTokenRevoked(token string) (bool, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM revoked_tokens WHERE token = ?", token).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Cleanup operations

// CleanupExpiredCodes removes expired authorization codes
func (d *Database) CleanupExpiredCodes() error {
	_, err := d.db.Exec("DELETE FROM authorization_codes WHERE expires_at < ?", time.Now())
	return err
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// Helper functions

func parseRedirectURIs(uris string) []string {
	if uris == "" {
		return []string{}
	}
	// Simple comma-separated parsing
	result := []string{}
	for _, uri := range splitString(uris, ",") {
		if uri != "" {
			result = append(result, uri)
		}
	}
	return result
}

func joinRedirectURIs(uris []string) string {
	result := ""
	for i, uri := range uris {
		if i > 0 {
			result += ","
		}
		result += uri
	}
	return result
}

func splitString(s, sep string) []string {
	result := []string{}
	current := ""
	for _, c := range s {
		if string(c) == sep {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
