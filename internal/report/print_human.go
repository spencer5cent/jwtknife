package report

import (
	"fmt"
	"io"
)

func PrintHuman(w io.Writer, r *Run) {
	// ===== SUCCESS SHORT-CIRCUIT =====
	for _, a := range r.JWTAttacks {
		if a.Outcome == OutcomeSuccess {
			fmt.Fprintln(w, "\n✅ SUCCESS")
			fmt.Fprintf(w, "Attack: %s\n", a.ID)
			if a.Note != "" {
				fmt.Fprintf(w, "Note: %s\n", a.Note)
			}
			for _, s := range a.Steps {
				if s.JWT.Token != "" {
					fmt.Fprintln(w, "\nForged JWT:")
					fmt.Fprintln(w, s.JWT.Token)
				}
			}
			fmt.Fprintln(w)
			return
		}
	}

	// ===== NORMAL REPORT (only if no success) =====
	fmt.Fprintln(w, "\n=== jwtknife report ===")
	fmt.Fprintf(w, "Started: %v\n", r.StartedAt)

	fmt.Fprintln(w, "\n[JWT]")
	fmt.Fprintf(w, "  alg: %s\n", r.JWT.Alg)
	if r.JWT.HasKid {
		fmt.Fprintf(w, "  kid: %s\n", r.JWT.Kid)
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
	}

	fmt.Fprintf(w, "\nAuth state: %s\n", r.AuthState)
	fmt.Fprintln(w, "=======================\n")
}
