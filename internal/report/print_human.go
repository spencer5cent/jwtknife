package report

import (
	"fmt"
	"io"
)

func PrintHuman(w io.Writer, r *Run) {
	fmt.Fprintln(w, "\n=== jwtknife report ===")
	fmt.Fprintf(w, "Started: %v\n", r.StartedAt)

	fmt.Fprintln(w, "\n[JWT]")
	fmt.Fprintf(w, "  alg: %s\n", r.JWT.Alg)
	if r.JWT.HasKid {
		fmt.Fprintf(w, "  kid: %s\n", r.JWT.Kid)
	}
	if r.JWT.HasJKU {
		fmt.Fprintf(w, "  jku: %s\n", r.JWT.JKU)
	}
	if r.JWT.HasJWK {
		fmt.Fprintln(w, "  jwk: present")
	}

	fmt.Fprintln(w, "\n[Baseline]")
	if r.Baseline != nil {
		printObs := func(label string, o *HTTPObs) {
			if o == nil {
				fmt.Fprintf(w, "  %s: (not tested)\n", label)
				return
			}
			if o.Err != "" {
				fmt.Fprintf(w, "  %s: error (%s)\n", label, o.Err)
				return
			}
			fmt.Fprintf(w, "  %s: status=%d body=%d\n", label, o.Status, o.BodyLen)
		}
		printObs("public", r.Baseline.Public)
		printObs("auth", r.Baseline.Auth)
		printObs("admin", r.Baseline.Admin)
	}

	fmt.Fprintln(w, "\n[JWT Attacks]")
	for _, a := range r.JWTAttacks {
		fmt.Fprintf(w, "- %s: %s\n", a.ID, a.Outcome)
		if a.Note != "" {
			fmt.Fprintf(w, "    note: %s\n", a.Note)
		}
		for _, s := range a.Steps {
			fmt.Fprintf(w, "    step: %s (%s)\n", s.Label, s.Details)
			if s.HTTP != nil && s.HTTP.Err == "" {
				fmt.Fprintf(w, "      http: %d (%d bytes)\n", s.HTTP.Status, s.HTTP.BodyLen)
			}
		}
	}

	fmt.Fprintf(w, "\nAuth state: %s\n", r.AuthState)
	if r.CallbackBaseURL != "" {
		fmt.Fprintf(w, "Callback base URL: %s\n", r.CallbackBaseURL)
	}
	fmt.Fprintln(w, "=======================\n")
}
