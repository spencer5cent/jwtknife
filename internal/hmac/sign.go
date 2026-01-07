package hmac

import (
	"github.com/golang-jwt/jwt/v5"

	"jwtknife/internal/jwtknifejwt"
)

// SignWithSecret returns a newly signed JWT using HS* and the provided secret.
// The payload is copied from the parsed JWT, with overrides applied.
func SignWithSecret(parsed *jwtknifejwt.Parsed, secret string, overrides map[string]any) (string, error) {
	claims := jwt.MapClaims{}

	// copy existing payload
	for k, v := range parsed.Payload {
		claims[k] = v
	}

	// apply overrides (e.g. sub=administrator)
	for k, v := range overrides {
		claims[k] = v
	}

	method := jwt.GetSigningMethod(parsed.Alg)
	if method == nil {
		return "", jwt.ErrInvalidKeyType
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header = parsed.Header

	return token.SignedString([]byte(secret))
}
