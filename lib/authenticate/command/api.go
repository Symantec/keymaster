package command

import (
	"github.com/Symantec/Dominator/lib/log"
)

type Authenticator struct {
	command string
	args    []string
	logger  log.Logger
}

// New creates a new Authenticator. The command used to authenticate the user
// is command and args may contain optional arguments to pass after the
// username. Log messages are written to logger. A new *Authenticator is
// returned if the command exists, else an error is returned.
func New(command string, args []string, logger log.Logger) (
	*Authenticator, error) {
	return newAuthenticator(command, args, logger)
}

// Authenticate will authenticate a user using the provided username and
// password. The password is provided on the standard input of the
// authentication command with a trailing newline.
// It returns true if the user is authenticated, else false (due to either
// invalid username or incorrect password).
func (au *Authenticator) Authenticate(username, password string) bool {
	return au.authenticate(username, password)
}
