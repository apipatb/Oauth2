package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// VerifyCodeChallenge verifies PKCE code challenge
func VerifyCodeChallenge(codeVerifier, codeChallenge, method string) bool {
	switch method {
	case "plain":
		return codeVerifier == codeChallenge
	case "S256":
		computed := generateS256Challenge(codeVerifier)
		return computed == codeChallenge
	default:
		return false
	}
}

// generateS256Challenge generates SHA256 challenge from verifier
func generateS256Challenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// ValidateCodeVerifier validates PKCE code verifier format
func ValidateCodeVerifier(verifier string) error {
	length := len(verifier)
	if length < 43 || length > 128 {
		return fmt.Errorf("code verifier must be between 43 and 128 characters")
	}
	return nil
}

// ValidateChallengeMethod validates PKCE challenge method
func ValidateChallengeMethod(method string) bool {
	return method == "plain" || method == "S256"
}
