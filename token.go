package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/dgrijalva/jwt-go"
)

var (
	keyPEM    []byte
	pubKeyPEM []byte
)

// GetToken returns a string that contain the token
func GetToken() (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	tokenString, err := t.SignedString(keyPEM)
	return tokenString, err
}

func initToken() {
	keyPair, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	})
	pubKeyANS1, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	if err != nil {
		panic(err)
	}
	pubKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyANS1,
	})
}
