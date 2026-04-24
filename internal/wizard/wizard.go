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

	jwta "github.com/spencer5cent/jwtknife/internal/attacks/jwt"
	"github.com/spencer5cent/jwtknife/internal/httpx"
	"github.com/spencer5cent/jwtknife/internal/jwtknifejwt"
	"github.com/spencer5cent/jwtknife/internal/report"
)

func Run(cfg Config, in io.Reader, out io.Writer) (*report.Run, error) {
	rd := bufio.NewReader(in)

	fmt.Fprintln(out, "jwtknife – JWT auth testing wizard")
	fmt.Fprintln(out)

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
	cfg.Placement = placement

	// ===== URLs =====
	pubURL := readURL(rd, out, "Unauthenticated URL (accessible without any JWT): ")
	authURL := readURL(rd, out, "Authenticated URL (accessible with the provided JWT): ")
	adminURL := readURL(rd, out, "Privilege-escalation target URL (admin or higher-privilege endpoint): ")
	cfg.PublicURL = pubURL.String()
	cfg.AuthURL = authURL.String()
	cfg.AdminURL = adminURL.String()
	cfg.RunJWK = true
	cfg.RunJKU = true
	cfg.PromptForHMACSecret = false

	if strings.HasPrefix(strings.ToUpper(parsed.Alg), "HS") {
		fmt.Fprintf(out, "\nThis JWT uses %s\n", parsed.Alg)
		fmt.Fprint(out, "If you already know or suspect the HMAC secret, enter it now (or press Enter to skip): ")
		line, _ := rd.ReadString('\n')
		cfg.HMACSecret = strings.TrimSpace(line)
	}

	// Interactive wizard defaults to the automatic KID traversal payload set.
	cfg.KIDMode = "auto"
	fmt.Fprintln(out, "\nPhase 1: JWT auth attacks")
	return Execute(cfg)
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

func Execute(cfg Config) (*report.Run, error) {
	cfg.Method = normalizeMethod(cfg.Method)
	cfg.RawJWT = strings.TrimSpace(strings.TrimPrefix(cfg.RawJWT, "Bearer "))
	cfg.SecondRawJWT = strings.TrimSpace(strings.TrimPrefix(cfg.SecondRawJWT, "Bearer "))

	if cfg.RawJWT == "" {
		return nil, fmt.Errorf("missing JWT")
	}
	if cfg.PublicURL == "" || cfg.AuthURL == "" || cfg.AdminURL == "" {
		return nil, fmt.Errorf("public, auth, and admin URLs are required")
	}
	if err := validatePlacement(cfg.Placement); err != nil {
		return nil, err
	}
	if cfg.CallbackURL != "" {
		if _, err := url.ParseRequestURI(cfg.CallbackURL); err != nil {
			return nil, fmt.Errorf("invalid callback URL: %w", err)
		}
	}

	parsed, err := jwtknifejwt.Parse(cfg.RawJWT)
	if err != nil {
		return nil, err
	}

	run := report.NewRun(time.Now())
	run.JWT.Raw = cfg.RawJWT
	run.JWT.Alg = parsed.Alg
	run.JWT.Header = parsed.HeaderJSON
	run.JWT.Payload = parsed.PayloadJSON
	run.JWT.HasKid = parsed.HasKid
	run.JWT.Kid = parsed.Kid
	run.JWT.HasJKU = parsed.HasJKU
	run.JWT.JKU = parsed.JKU
	run.JWT.HasJWK = parsed.HasJWK

	client := httpx.NewClient(httpx.ClientOpts{
		Timeout:         10 * time.Second,
		FollowRedirects: false,
		MaxRequests:     50,
	})

	run.Baseline = report.NewBaseline()
	run.Baseline.Public = report.FromHTTPResult(client.Do(httpx.RequestPlan{
		Label:     "public",
		URL:       cfg.PublicURL,
		Method:    cfg.Method,
		JWT:       cfg.RawJWT,
		Placement: cfg.Placement,
	}))
	run.Baseline.Auth = report.FromHTTPResult(client.Do(httpx.RequestPlan{
		Label:     "auth",
		URL:       cfg.AuthURL,
		Method:    cfg.Method,
		JWT:       cfg.RawJWT,
		Placement: cfg.Placement,
	}))
	if cfg.AdminURL == cfg.AuthURL {
		run.Baseline.Admin = run.Baseline.Auth
	} else {
		run.Baseline.Admin = report.FromHTTPResult(client.Do(httpx.RequestPlan{
			Label:     "admin",
			URL:       cfg.AdminURL,
			Method:    cfg.Method,
			JWT:       cfg.RawJWT,
			Placement: cfg.Placement,
		}))
	}

	input := jwta.AttackInput{
		ParsedJWT:    parsed,
		RawJWT:       cfg.RawJWT,
		SecondRawJWT: cfg.SecondRawJWT,
		Client:       client,
		Baseline:     run.Baseline,
		Targets: httpx.Targets{
			PublicURL: cfg.PublicURL,
			AuthURL:   cfg.AuthURL,
			AdminURL:  cfg.AdminURL,
			Method:    cfg.Method,
			Placement: cfg.Placement,
		},
		Callback:     cfg.CallbackURL,
		HMACSecret:   []byte(cfg.HMACSecret),
		HMACWordlist: cfg.HMACWordlist,
		AllowResign:  cfg.PromptForHMACSecret,
	}

	for _, atk := range jwta.DefaultAttacks() {
		res := atk.Run(input)
		run.JWTAttacks = append(run.JWTAttacks, res)

		if res.Outcome == report.OutcomeSuccess && !cfg.Exhaustive {
			run.AuthState = report.EvaluateAuthState(run.Baseline, run.JWTAttacks)
			return run, nil
		}
	}

	if cfg.RunJWK {
		run.JWTAttacks = append(run.JWTAttacks, jwta.NewJWKHeaderAttack().Run(input))
	}

	if cfg.RunJKU {
		jkuAttack := jwta.NewJKUAttack()
		if cfg.CallbackURL == "" {
			run.JWTAttacks = append(run.JWTAttacks, jkuAttack.Run(input))
		} else {
			run.CallbackBaseURL = cfg.CallbackURL
			run.JWTAttacks = append(run.JWTAttacks, jkuAttack.Run(input))
		}
	}

	switch strings.ToLower(strings.TrimSpace(cfg.KIDMode)) {
	case "", "auto":
		run.JWTAttacks = append(run.JWTAttacks, jwta.NewKidTraversalAttack().Run(input))
	case "custom":
		if strings.TrimSpace(cfg.CustomKID) == "" {
			return nil, fmt.Errorf("kid mode custom requires --kid-value")
		}
		customInput := input
		customInput.CustomKID = strings.TrimSpace(cfg.CustomKID)
		run.JWTAttacks = append(run.JWTAttacks, jwta.NewKidTraversalAttack().Run(customInput))
	case "skip":
		// no-op
	default:
		return nil, fmt.Errorf("invalid kid mode %q", cfg.KIDMode)
	}

	run.AuthState = report.EvaluateAuthState(run.Baseline, run.JWTAttacks)
	return run, nil
}

func normalizeMethod(method string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		return "GET"
	}
	return m
}

func validatePlacement(p httpx.JWTPlacement) error {
	switch p.Kind {
	case httpx.PlaceAuthorizationBearer:
		return nil
	case httpx.PlaceCookie, httpx.PlaceHeader:
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("placement name is required for cookie and header placement")
		}
		return nil
	default:
		return fmt.Errorf("invalid JWT placement")
	}
}
