package jwt

import (
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// CheckTokenAge validates that a JWT token's iat claim is within the given
// maxAge duration. Returns an error if the claims are unparseable, the iat
// claim is missing, or the token is too old.
func CheckTokenAge(token *gojwt.Token, maxAge time.Duration) error {
	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok {
		return fmt.Errorf("token has invalid claims format (user=%s)", UserIDFromToken(token))
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		return fmt.Errorf("token missing iat claim (user=%s)", UserIDFromToken(token))
	}

	issuedAt := time.Unix(int64(iat), 0)
	tokenAge := time.Since(issuedAt)
	if tokenAge > maxAge {
		return fmt.Errorf("token expired for user=%s: age=%v, max=%v", userIDFromClaims(claims), tokenAge, maxAge)
	}

	return nil
}

// UserIDFromToken extracts a human-readable user identifier from a JWT token
// for use in error messages. Returns "unknown" if the token or claims are nil.
func UserIDFromToken(token *gojwt.Token) string {
	if token == nil {
		return "unknown"
	}
	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok {
		return "unknown"
	}
	return userIDFromClaims(claims)
}

// userIDFromClaims extracts a user identifier from JWT claims, trying sub,
// user_id, and email in order.
func userIDFromClaims(claims gojwt.MapClaims) string {
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}
	if userID, ok := claims["user_id"].(string); ok && userID != "" {
		return userID
	}
	if email, ok := claims["email"].(string); ok && email != "" {
		return email
	}
	return "unknown"
}
