package auth

// Config struct contains the authentication configuration
type Config struct {
	Identification loginFn
	Verification   string
}

// User structure
type User struct {
	ID           int64  `db:"id"`
	Username     string `db:"username"`
	FullName     string `db:"fullName"`
	PasswordHash string `db:"passwordHash"`
	PasswordSalt string `db:"passwordSalt"`
	Role         string `db:"role"`
	IsDisabled   bool   `db:"isDisabled"`
}

type loginFn func(string, string) (*User, error)

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

// Advanced function allows a third party Identification driver
func (a *Config) Advanced(driver loginFn) {
	a.Identification = driver
	a.Verification = "restricted"

	initToken()
}
