package wizard

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	jwta "jwtknife/internal/attacks/jwt"
	"jwtknife/internal/httpx"
	"jwtknife/internal/jwtknifejwt"
	"jwtknife/internal/report"
)

func Run(cfg Config, in io.Reader, out io.Writer) (*report.Run, error) {
	rd := bufio.NewReader(in)

	fmt.Fprintln(out, "jwtknife – Phase 0 (setup) + Phase 1 (JWT auth testing)\n")

	// ===== JWT input =====
	if strings.TrimSpace(cfg.RawJWT) == "" {
		fmt.Fprint(out, "Paste the JWT (you can include 'Bearer '): ")
		j, _ := rd.ReadString('\n')
		cfg.RawJWT = strings.TrimSpace(j)
	}
	cfg.RawJWT = strings.TrimPrefix(cfg.RawJWT, "Bearer ")

	parsed, err := jwtknifejwt.Parse(cfg.RawJWT)
	if err != nil {
		return nil, err
	}

	run := report.NewRun(time.Now())
	run.JWT.Raw = cfg.RawJWT
	run.JWT.Alg = parsed.Alg
	run.JWT.HasKid = parsed.HasKid
	run.JWT.Kid = parsed.Kid

	fmt.Fprintf(out, "\nDecoded JWT:\n  alg: %s\n", parsed.Alg)
	if parsed.HasKid {
		fmt.Fprintf(out, "  kid: %s\n", parsed.Kid)
	}

	// ===== JWT placement =====
	fmt.Fprintln(out, "\nWhere is the JWT sent?")
	fmt.Fprintln(out, "  1) Authorization: Bearer <token>")
	fmt.Fprintln(out, "  2) Cookie")
	fmt.Fprintln(out, "  3) Custom header")
	fmt.Fprint(out, "Choose [1-3]: ")

	c, _ := rd.ReadString('\n')
	c = strings.TrimSpace(c)

	var placement httpx.JWTPlacement
	switch c {
	case "2":
		fmt.Fprint(out, "Cookie name: ")
		n, _ := rd.ReadString('\n')
		placement = httpx.JWTPlacement{Kind: httpx.PlaceCookie, Name: strings.TrimSpace(n)}
	case "3":
		fmt.Fprint(out, "Header name: ")
		n, _ := rd.ReadString('\n')
		placement = httpx.JWTPlacement{Kind: httpx.PlaceHeader, Name: strings.TrimSpace(n)}
	default:
		placement = httpx.JWTPlacement{Kind: httpx.PlaceAuthorizationBearer}
	}

	// ===== URLs =====
	pubURL := readURL(rd, out, "Public URL (no auth required): ")
	authURL := readURL(rd, out, "JWT-required URL: ")
	adminURL := readURL(rd, out, "Admin-only URL: ")

	fmt.Fprint(out, "Callback base URL (optional): ")
	cb, _ := rd.ReadString('\n')
	cb = strings.TrimSpace(cb)

	// ===== HTTP client =====
	client := httpx.NewClient(httpx.ClientOpts{
		Timeout:         10 * time.Second,
		FollowRedirects: false,
		MaxRequests:     50,
	})

	// ===== Phase 0: baseline =====
	run.Baseline = report.NewBaseline()

	run.Baseline.Public = report.FromHTTPResult(client.Do(httpx.RequestPlan{
		Label:     "public",
		URL:       pubURL.String(),
		Method:    "GET",
		JWT:       cfg.RawJWT,
		Placement: placement,
	}))

	run.Baseline.Auth = report.FromHTTPResult(client.Do(httpx.RequestPlan{
		Label:     "auth",
		URL:       authURL.String(),
		Method:    "GET",
		JWT:       cfg.RawJWT,
		Placement: placement,
	}))

	run.Baseline.Admin = report.FromHTTPResult(client.Do(httpx.RequestPlan{
		Label:     "admin",
		URL:       adminURL.String(),
		Method:    "GET",
		JWT:       cfg.RawJWT,
		Placement: placement,
	}))

	// ===== Phase 1: attacks =====
	fmt.Fprintln(out, "\nPhase 1: JWT auth attacks")

	input := jwta.AttackInput{
		ParsedJWT: parsed,
		RawJWT:    cfg.RawJWT,
		Client:    client,
		Baseline:  run.Baseline,
		Callback:  cb,
		Targets: httpx.Targets{
			PublicURL: pubURL.String(),
			AuthURL:   authURL.String(),
			AdminURL:  adminURL.String(),
			Method:    "GET",
			Placement: placement,
		},
	}

	run.JWTAttacks = []report.AttackResult{
		jwta.NewUnverifiedSignatureAttack().Run(input),
		jwta.NewAlgNoneAttack().Run(input),
		jwta.NewJWKHeaderAttack().Run(input), // Lab 4
	}

	run.AuthState = report.EvaluateAuthState(run.Baseline, run.JWTAttacks)

	// ===== Post-forge menu =====
	var forgedJWT string
	for _, a := range run.JWTAttacks {
		for _, s := range a.Steps {
			if s.JWT.Token != "" {
				forgedJWT = s.JWT.Token
				break
			}
		}
	}

	if forgedJWT != "" {
		fmt.Fprintln(out, "\nForged JWT available:")
		fmt.Fprintln(out, "  1) Print forged JWT")
		fmt.Fprintln(out, "  2) Send admin request with forged JWT")
		fmt.Fprintln(out, "  3) Skip")
		fmt.Fprint(out, "Choose [1-3]: ")

		ch, _ := rd.ReadString('\n')
		ch = strings.TrimSpace(ch)

		switch ch {
		case "1":
			fmt.Fprintln(out, forgedJWT)
		case "2":
			res := client.Do(httpx.RequestPlan{
				Label:     "admin-forged",
				URL:       adminURL.String(),
				Method:    "GET",
				JWT:       forgedJWT,
				Placement: placement,
			})
			fmt.Fprintf(out, "[+] Admin response: %d (%d bytes)\n",
				res.Status, res.BodyLen)
		}
	}

	return run, nil
}

// ===== helper =====
func readURL(rd *bufio.Reader, out io.Writer, label string) *url.URL {
	for {
		fmt.Fprint(out, label)
		s, _ := rd.ReadString('\n')
		u, err := url.Parse(strings.TrimSpace(s))
		if err == nil && u.Scheme != "" {
			return u
		}
		fmt.Fprintln(out, "Invalid URL, try again.")
	}
}
