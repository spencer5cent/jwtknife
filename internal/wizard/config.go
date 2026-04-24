package wizard

import "github.com/spencer5cent/jwtknife/internal/httpx"

// Config is the runtime configuration passed from main.
type Config struct {
	RawJWT       string // the primary JWT provided by the user
	SecondRawJWT string // optional second JWT (for alg-confusion / sig2n style attacks)
	RawRequest   string // optional raw HTTP request
	Method       string // GET / POST

	Placement httpx.JWTPlacement

	PublicURL string
	AuthURL   string
	AdminURL  string

	RunJWK      bool
	RunJKU      bool
	CallbackURL string

	KIDMode      string // auto | custom | skip
	CustomKID    string
	HMACSecret   string
	HMACWordlist string

	// If true, run all attacks even after a success (no short-circuiting)
	Exhaustive bool

	PromptForHMACSecret bool
}
