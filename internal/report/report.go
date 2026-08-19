package report

import "time"

type Outcome string

const (
	OutcomeSuccess     Outcome = "success"
	OutcomeInteresting Outcome = "interesting"
	OutcomeNoEffect    Outcome = "no-effect"
	OutcomeError       Outcome = "error"
)

type Run struct {
	StartedAt       time.Time
	JWT             JWTSection
	Baseline        *Baseline
	JWTAttacks      []AttackResult
	AuthState       string
	CallbackBaseURL string
}

type JWTSection struct {
	Raw     string
	Alg     string
	Header  string
	Payload string
	HasKid  bool
	Kid     string
	HasJKU  bool
	JKU     string
	HasJWK  bool
}

type Baseline struct {
	Public *HTTPObs
	Auth   *HTTPObs
	Admin  *HTTPObs
}

type HTTPObs struct {
	Status               int
	BodyLen              int
	BodySHA256           string
	BodyNormalizedSHA256 string
	Duration             time.Duration
	Err                  string
}

type JWTInfo struct {
	Token string
}

type AttackResult struct {
	ID      string
	Outcome Outcome
	Note    string            // optional human note
	Notes   map[string]string // machine-readable extras (forged_jwt, secret, etc)
	Errors  []string
	Steps   []Step
}

type Step struct {
	Label     string
	Details   string
	HTTP      *HTTPObs // primary request/response
	ReuseHTTP *HTTPObs // optional post-exploit reuse check
	JWT       JWTInfo  // forged or mutated JWT

	// Variant identifies how the JWT was constructed or abused
	// examples: "raw-pem", "base64-pem", "es256-confusion"
	Variant string

	// True if this technique is known to be lab-style or highly artificial
	LabSpecific bool
}

func NewRun(t time.Time) *Run {
	return &Run{StartedAt: t}
}

func NewBaseline() *Baseline {
	return &Baseline{}
}

func NewAttackResult(id string) AttackResult {
	return AttackResult{
		ID:    id,
		Notes: map[string]string{},
	}
}
