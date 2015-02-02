package auth

// Config struct contains the authentication configuration
type Config struct {
	Identification loginFn
	Verification   string
}

type loginFn func(string, string) bool

var (
	user, pass string
)

// New function initalizes and returns a Config struct
func New() Config {
	a := Config{}
	return a
}

// None function sets the Config struct in order to disable authentication
func (a *Config) None() {
	a.Identification = none
	a.Verification = "none"
}

// Simple function sets the Config struct in order to enable simple authentication based on provided user and pass
func (a *Config) Simple(u, p string) {
	a.Identification = simple
	a.Verification = "restricted"

	user = u
	pass = p

	initToken()
}
