package auth

import (
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
	"github.com/palourde/logger"
)

var (
	rsa, pub []byte
)

const (
	rsaPath = "./keys/uchiwa.rsa"
	pubPath = "./keys/uchiwa.rsa.pub"
)

// GetToken returns a string that contain the token
func GetToken() (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	tokenString, err := t.SignedString(rsa)
	return tokenString, err
}

func initToken() {
	var err error

	rsa, err = ioutil.ReadFile(rsaPath)
	if err != nil {
		logger.Fatalf("Could not open the private key %s", rsaPath)
		return
	}

	pub, err = ioutil.ReadFile(pubPath)
	if err != nil {
		logger.Fatalf("Could not open the public key %s", pubPath)
		return
	}
}
