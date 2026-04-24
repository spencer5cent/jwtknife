package jwt

import (
	"github.com/spencer5cent/jwtknife/internal/httpx"
	"github.com/spencer5cent/jwtknife/internal/jwtknifejwt"
	"github.com/spencer5cent/jwtknife/internal/report"
)

type Attack interface {
	Name() string
	Run(AttackInput) report.AttackResult
}

// DefaultAttacks returns the standard set of JWT attacks executed in Phase 1.
// Wizard code may choose to call these explicitly or selectively.
func DefaultAttacks() []Attack {
	return []Attack{
		NewUnverifiedSignatureAttack(),
		NewAlgNoneAttack(),
		NewWeakHMACAttack(),
		NewAlgConfusionAttack(),
		NewAlgConfusionSig2NAttack(),
	}
}

type AttackInput struct {
	ParsedJWT    *jwtknifejwt.Parsed
	RawJWT       string
	SecondRawJWT string
	Targets      httpx.Targets
	Client       *httpx.Client
	Baseline     *report.Baseline
	Callback     string

	// Optional custom inputs for specific attacks
	CustomKID    string
	HMACSecret   []byte
	HMACWordlist string
	AllowResign  bool
}
