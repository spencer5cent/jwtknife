package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spencer5cent/jwtknife/internal/httpx"
	"github.com/spencer5cent/jwtknife/internal/report"
	"github.com/spencer5cent/jwtknife/internal/wizard"
)

func main() {
	var exhaustive bool
	var nonInteractive bool
	var output string
	var rawJWT string
	var jwtFile string
	var secondJWT string
	var secondJWTFile string
	var publicURL string
	var authURL string
	var adminURL string
	var method string
	var placement string
	var placementName string
	var callbackURL string
	var kidMode string
	var kidValue string
	var hmacSecret string
	var hmacWordlist string
	var runJWK bool
	var runJKU bool

	flag.BoolVar(&exhaustive, "exhaustive", false, "run all attacks even after a successful exploit")
	flag.BoolVar(&nonInteractive, "non-interactive", false, "run from flags instead of the interactive wizard")
	flag.StringVar(&output, "output", "human", "output format: human or json")
	flag.StringVar(&rawJWT, "jwt", "", "JWT value (you can include Bearer)")
	flag.StringVar(&jwtFile, "jwt-file", "", "path to a file containing a JWT")
	flag.StringVar(&secondJWT, "second-jwt", "", "optional second JWT for sig2n-style attacks")
	flag.StringVar(&secondJWTFile, "second-jwt-file", "", "path to a file containing the second JWT")
	flag.StringVar(&publicURL, "public-url", "", "unauthenticated URL")
	flag.StringVar(&authURL, "auth-url", "", "authenticated URL for the provided JWT")
	flag.StringVar(&adminURL, "admin-url", "", "privilege escalation target URL")
	flag.StringVar(&method, "method", "GET", "HTTP method to use for baseline and attack requests")
	flag.StringVar(&placement, "placement", "authorization", "JWT placement: authorization, cookie, or header")
	flag.StringVar(&placementName, "placement-name", "", "cookie or header name when placement is cookie or header")
	flag.StringVar(&callbackURL, "callback-url", "", "hosted jwks.json URL for JKU testing")
	flag.StringVar(&kidMode, "kid-mode", "auto", "KID traversal mode: auto, custom, or skip")
	flag.StringVar(&kidValue, "kid-value", "", "custom kid value when --kid-mode=custom")
	flag.StringVar(&hmacSecret, "hmac-secret", "", "known or suspected HMAC secret for HS* tokens")
	flag.StringVar(&hmacWordlist, "hmac-wordlist", "", "wordlist path for hashcat-based HS* secret cracking")
	flag.BoolVar(&runJWK, "jwk", true, "run the JWK header injection attack")
	flag.BoolVar(&runJKU, "jku", true, "run the JKU header injection attack")
	flag.Parse()

	if strings.EqualFold(output, "json") {
		runJSONMode(func() (*report.Run, error) {
			return runCLI(nonInteractive || hasAutomationInputs(rawJWT, jwtFile, secondJWT, secondJWTFile, publicURL, authURL, adminURL, callbackURL, placementName, hmacSecret, kidValue), wizard.Config{
				RawJWT:       mustLoadJWT(rawJWT, jwtFile),
				SecondRawJWT: mustLoadJWT(secondJWT, secondJWTFile),
				Method:       method,
				Placement:    mustPlacement(placement, placementName),
				PublicURL:    publicURL,
				AuthURL:      authURL,
				AdminURL:     adminURL,
				RunJWK:       runJWK,
				RunJKU:       runJKU,
				CallbackURL:  callbackURL,
				KIDMode:      kidMode,
				CustomKID:    kidValue,
				HMACSecret:   hmacSecret,
				HMACWordlist: hmacWordlist,
				Exhaustive:   exhaustive,
			})
		})
		return
	}

	run, err := runCLI(nonInteractive || hasAutomationInputs(rawJWT, jwtFile, secondJWT, secondJWTFile, publicURL, authURL, adminURL, callbackURL, placementName, hmacSecret, kidValue), wizard.Config{
		RawJWT:       mustLoadJWT(rawJWT, jwtFile),
		SecondRawJWT: mustLoadJWT(secondJWT, secondJWTFile),
		Method:       method,
		Placement:    mustPlacement(placement, placementName),
		PublicURL:    publicURL,
		AuthURL:      authURL,
		AdminURL:     adminURL,
		RunJWK:       runJWK,
		RunJKU:       runJKU,
		CallbackURL:  callbackURL,
		KIDMode:      kidMode,
		CustomKID:    kidValue,
		HMACSecret:   hmacSecret,
		HMACWordlist: hmacWordlist,
		Exhaustive:   exhaustive,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	report.PrintHuman(os.Stdout, run)
}

func runCLI(nonInteractive bool, cfg wizard.Config) (*report.Run, error) {
	if nonInteractive {
		return wizard.Execute(cfg)
	}
	return wizard.Run(cfg, os.Stdin, os.Stdout)
}

func hasAutomationInputs(values ...string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func mustLoadJWT(raw, path string) string {
	if strings.TrimSpace(raw) != "" && strings.TrimSpace(path) != "" {
		fmt.Fprintln(os.Stderr, "error: use only one of the inline JWT or JWT file flags")
		os.Exit(2)
	}
	if strings.TrimSpace(path) == "" {
		return strings.TrimSpace(raw)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading JWT file %q: %v\n", path, err)
		os.Exit(2)
	}

	re := regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	match := re.FindString(string(data))
	if match == "" {
		fmt.Fprintf(os.Stderr, "error: no JWT found in file %q\n", path)
		os.Exit(2)
	}
	return match
}

func mustPlacement(kind, name string) httpx.JWTPlacement {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "authorization", "bearer", "auth":
		return httpx.JWTPlacement{Kind: httpx.PlaceAuthorizationBearer}
	case "cookie":
		return httpx.JWTPlacement{Kind: httpx.PlaceCookie, Name: strings.TrimSpace(name)}
	case "header":
		return httpx.JWTPlacement{Kind: httpx.PlaceHeader, Name: strings.TrimSpace(name)}
	default:
		fmt.Fprintf(os.Stderr, "error: invalid placement %q\n", kind)
		os.Exit(2)
		return httpx.JWTPlacement{}
	}
}

func runJSONMode(fn func() (*report.Run, error)) {
	run, err := fn()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(run); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
