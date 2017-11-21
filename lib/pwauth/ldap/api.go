package ldap

import (
	"crypto/x509"
	"github.com/Symantec/Dominator/lib/log"
	//"github.com/Symantec/Dominator/lib/log/debuglogger"
	"net/url"
)

type PasswordAuthenticator struct {
	ldapURL     []*url.URL
	bindPattern []string
	timeoutSecs uint
	rootCAs     *x509.CertPool
	logger      log.DebugLogger
}

func New(url []string, bindPattern []string, timeoutSecs uint, rootCAs *x509.CertPool, logger log.DebugLogger) (
	*PasswordAuthenticator, error) {
	return newAuthenticator(url, bindPattern, timeoutSecs, rootCAs, logger)
}

// PasswordAuthenticate will authenticate a user using the provided username and
// password. The password is provided on the standard input of the
// authentication command.
// It returns true if the user is authenticated, else false (due to either
// invalid username or incorrect password), and an error.
func (pa *PasswordAuthenticator) PasswordAuthenticate(username string,
	password []byte) (bool, error) {
	return pa.passwordAuthenticate(username, password)
}
