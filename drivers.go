package auth

func none(u, p string) bool {
	return true
}

func simple(u, p string) bool {
	if u == user && p == pass {
		return true
	}
	return false
}
