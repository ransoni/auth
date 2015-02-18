package auth

import "fmt"

func none(u, p string) (*User, error) {
	return &User{}, nil
}

func simple(u, p string) (*User, error) {
	if u == user && p == pass {
		return &User{ID: 0, Username: u, FullName: u, PasswordHash: "", PasswordSalt: "", Role: "operator"}, nil
	}
	return &User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
}
