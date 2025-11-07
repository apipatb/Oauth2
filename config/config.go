package config

import (
	"fmt"
	"os"
)

// Config holds application configuration
type Config struct {
	// Server
	ServerPort string

	// Database
	DatabaseType string // "sqlite" or "postgres"
	DatabaseURL  string

	// JWT
	JWTSecret string

	// Token lifetimes
	AccessTokenLifetime  int // seconds
	RefreshTokenLifetime int // seconds
	AuthCodeLifetime     int // seconds
}

// LoadConfig loads configuration from environment variables with defaults
func LoadConfig() *Config {
	return &Config{
		// Server defaults
		ServerPort: getEnv("SERVER_PORT", "8080"),

		// Database defaults
		DatabaseType: getEnv("DATABASE_TYPE", "sqlite"),
		DatabaseURL:  getEnv("DATABASE_URL", "./oauth2.db"),

		// JWT secret (should be changed in production!)
		JWTSecret: getEnv("JWT_SECRET", "your-secret-key-change-this-in-production"),

		// Token lifetimes (in seconds)
		AccessTokenLifetime:  getEnvInt("ACCESS_TOKEN_LIFETIME", 3600),      // 1 hour
		RefreshTokenLifetime: getEnvInt("REFRESH_TOKEN_LIFETIME", 2592000),  // 30 days
		AuthCodeLifetime:     getEnvInt("AUTH_CODE_LIFETIME", 600),          // 10 minutes
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		// Simple conversion, in production use strconv.Atoi with error handling
		var intValue int
		if _, err := fmt.Sscanf(value, "%d", &intValue); err == nil {
			return intValue
		}
	}
	return defaultValue
}
