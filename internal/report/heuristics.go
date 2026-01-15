package report

// IsAdminSuccess determines whether an attack step likely achieved admin access.
//
// IMPORTANT: This should be conservative. We do NOT infer success from hitting a
// particular endpoint or from vague "side effects". We only treat clearly
// successful HTTP statuses as success, with a small allowance for redirect-based
// admin flows commonly seen in apps/labs.
func IsAdminSuccess(base *Baseline, got *HTTPObs) bool {
	if got == nil || got.Err != "" || base == nil || base.Admin == nil {
		return false
	}

	// Direct success: 2xx
	if got.Status >= 200 && got.Status < 300 {
		return true
	}

	// Redirect-based success: 3xx can indicate a successful admin action (e.g. delete -> redirect).
	// To avoid obvious false positives (like redirect-to-login), only treat 3xx as success
	// when the baseline admin response is NOT already a redirect.
	if got.Status >= 300 && got.Status < 400 {
		if base.Admin.Status < 300 || base.Admin.Status >= 400 {
			return true
		}
	}

	return false
}

func IsInteresting(base *Baseline, got *HTTPObs) bool {
	if got == nil || got.Err != "" {
		return false
	}
	return true
}

func EvaluateAuthState(base *Baseline, atks []AttackResult) string {
	for _, a := range atks {
		if a.Outcome == OutcomeSuccess {
			return "admin"
		}
	}
	return "unknown"
}
