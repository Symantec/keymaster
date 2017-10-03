package command

import (
	"bytes"
	"os/exec"

	"github.com/Symantec/Dominator/lib/log"
)

func newAuthenticator(command string, args []string, logger log.Logger) (
	*PasswordAuthenticator, error) {
	command, err := exec.LookPath(command)
	if err != nil {
		return nil, err
	}
	return &PasswordAuthenticator{command, args, logger}, nil
}

func (pa *PasswordAuthenticator) passwordAuthenticate(username string,
	password []byte) (bool, error) {
	args := []string{username}
	args = append(args, pa.args...)
	cmd := exec.Command(pa.command, args...)
	cmd.Stdin = bytes.NewReader(password)
	if err := cmd.Run(); err != nil {
		pa.logger.Println(err)
		return false, err
	}
	return true, nil
}
