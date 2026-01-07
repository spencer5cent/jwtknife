package wizard

// Config is the runtime configuration passed from main
type Config struct {
	RawJWT     string // the JWT provided by the user
	RawRequest string // optional raw HTTP request
	Method     string // GET / POST (future use)
}
