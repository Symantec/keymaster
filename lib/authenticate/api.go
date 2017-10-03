package authenticate

// Authenticator is an interface type that defines how to authenticate a user
// with a username and password.
type Authenticator interface {
	// Authenticate will authenticate a user using the provided username and
	// password. It returns true if the user is authenticated, else false (due
	// to either invalid username or incorrect password).
	Authenticate(username, password string) bool
}
