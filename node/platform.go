package main

import "os/user"

// currentUser restituisce l'utente sotto cui gira il nodo.
func currentUser() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}
