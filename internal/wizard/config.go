package wizard

// Config is the runtime configuration passed from main
type Config struct {
	RawJWT       string // the primary JWT provided by the user
	SecondRawJWT string // optional second JWT (for alg-confusion / sig2n style attacks)
	RawRequest   string // optional raw HTTP request
	Method       string // GET / POST (future use)

	// If true, run all attacks even after a success (no short-circuiting)
	Exhaustive bool
}
