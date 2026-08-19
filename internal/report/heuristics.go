package report

// IsAdminSuccess determines whether an attack step likely achieved admin access.
//
// A forged token is successful only when it reproduces the real-token admin
// response across an observed authentication boundary. A 2xx by itself is never
// proof: public SPA shells and marketing pages commonly return 200 for everything.
func IsAdminSuccess(base *Baseline, got *HTTPObs) bool {
	if got == nil || got.Err != "" || base == nil || base.Public == nil || base.Admin == nil {
		return false
	}
	if base.Public.Err != "" || base.Admin.Err != "" {
		return false
	}
	// First prove that the captured real token changes the admin endpoint.
	if sameHTTPObservation(base.Public, base.Admin) {
		return false
	}
	// Then require the forged token to reproduce that authenticated response.
	return sameHTTPObservation(got, base.Admin) && !sameHTTPObservation(got, base.Public)
}

func sameHTTPObservation(a, b *HTTPObs) bool {
	if a == nil || b == nil || a.Status != b.Status {
		return false
	}
	if a.BodyNormalizedSHA256 != "" && b.BodyNormalizedSHA256 != "" {
		return a.BodyNormalizedSHA256 == b.BodyNormalizedSHA256
	}
	if a.BodySHA256 != "" && b.BodySHA256 != "" {
		return a.BodySHA256 == b.BodySHA256
	}
	return a.BodyLen == b.BodyLen
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
