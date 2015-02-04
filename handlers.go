package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/palourde/logger"
)

// Response returns a JSON
type Response map[string]interface{}

func (r Response) String() (s string) {
	b, err := json.Marshal(r)
	if err != nil {
		s = ""
		return
	}
	s = string(b)
	return
}

// publicHandler enforce no authentication
func publicHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// restrictedHandler enforce authentication by validating a token
func restrictedHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := jwt.ParseFromRequest(r, func(t *jwt.Token) (interface{}, error) {
			return pubKeyPEM, nil
		})
		if token != nil && err == nil {
			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, err.Error(), http.StatusForbidden)
			}
		} else {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
	})
}

// Authenticate calls the proper handler based on whether authentication is enabled or not
func (a *Config) Authenticate(next http.Handler) http.Handler {
	if a.Verification == "none" {
		return publicHandler(next)
	}
	return restrictedHandler(next)
}

// GetIdentification retrieves the user & pass from a POST and authenticates the user against the Identification driver
func (a *Config) GetIdentification() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/#/login", http.StatusFound)
			return
		}

		decoder := json.NewDecoder(r.Body)
		var data interface{}
		err := decoder.Decode(&data)
		if err != nil {
			logger.Warningf("Could not decode the body: %s", err)
			http.Error(w, "", http.StatusInternalServerError)
		}
		m, ok := data.(map[string]interface{})
		if !ok {
			logger.Warningf("Could not assert the body: %s", err)
			http.Error(w, "", http.StatusInternalServerError)
		}

		user := m["user"].(string)
		pass := m["pass"].(string)
		if user == "" || pass == "" {
			http.Error(w, "", http.StatusUnauthorized)
		}

		// validate the user with the Login authentication driver
		successful := a.Identification(user, pass)
		if !successful {
			logger.Warningf("Login failed for the user %s", err)
			http.Error(w, "", http.StatusUnauthorized)
		}

		token, err := GetToken()
		if err != nil {
			logger.Warningf("Could not create the token: %s", err)
			http.Error(w, "", http.StatusInternalServerError)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, Response{"token": token})
		return
	})
}
