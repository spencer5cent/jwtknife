package jwtknifejwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid,omitempty"`
}

// GenerateRSAJWK generates a fresh RSA keypair and returns
// the private key and a JWK representation of the public key.
func GenerateRSAJWK(kid string) (*rsa.PrivateKey, map[string]any, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	pub := priv.PublicKey

	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	jwk := JWK{
		Kty: "RSA",
		N:   n,
		E:   e,
	}

	if kid != "" {
		jwk.Kid = kid
	}

	// convert to generic map for header injection
	jwkMap := map[string]any{
		"kty": jwk.Kty,
		"n":   jwk.N,
		"e":   jwk.E,
	}
	if jwk.Kid != "" {
		jwkMap["kid"] = jwk.Kid
	}

	return priv, jwkMap, nil
}
