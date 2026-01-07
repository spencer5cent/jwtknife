package report

func IsAdminSuccess(base *Baseline, got *HTTPObs) bool {
	if got == nil || got.Err != "" {
		return false
	}
	return got.Status >= 200 && got.Status < 300
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
