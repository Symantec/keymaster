package command

import (
	"os/exec"
	"strings"

	"github.com/Symantec/Dominator/lib/log"
)

func newAuthenticator(command string, args []string, logger log.Logger) (
	*Authenticator, error) {
	command, err := exec.LookPath(command)
	if err != nil {
		return nil, err
	}
	return &Authenticator{command, args, logger}, nil
}

func (au *Authenticator) authenticate(username, password string) bool {
	args := []string{username}
	args = append(args, au.args...)
	cmd := exec.Command(au.command, args...)
	cmd.Stdin = strings.NewReader(password + "\n")
	if err := cmd.Run(); err != nil {
		au.logger.Println(err)
		return false
	}
	return true
}
