package jwt

import (
	"jwtknife/internal/httpx"
	"jwtknife/internal/jwtknifejwt"
	"jwtknife/internal/report"
)

type Attack interface {
	Name() string
	Run(AttackInput) report.AttackResult
}

type AttackInput struct {
	ParsedJWT *jwtknifejwt.Parsed
	RawJWT    string
	Targets   httpx.Targets
	Client    *httpx.Client
	Baseline  *report.Baseline
	Callback  string
}
