package ldap

import (
	"crypto/x509"
	//"errors"
	"fmt"
	"time"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/keymaster/lib/authutil"
)

const defaultCacheDuration = time.Hour * 96

func newAuthenticator(urllist []string, bindPattern []string,
	timeoutSecs uint, rootCAs *x509.CertPool, logger log.DebugLogger) (
	*PasswordAuthenticator, error) {
	var authenticator PasswordAuthenticator
	for _, stringURL := range urllist {
		url, err := authutil.ParseLDAPURL(stringURL)
		if err != nil {
			return nil, err
		}
		authenticator.ldapURL = append(authenticator.ldapURL, url)
	}
	authenticator.bindPattern = bindPattern
	authenticator.timeoutSecs = timeoutSecs
	authenticator.rootCAs = rootCAs
	authenticator.logger = logger
	authenticator.expirationDuration = defaultCacheDuration
	authenticator.cachedCredentials = make(map[string]cacheCredentialEntry)
	return &authenticator, nil
}

func convertToBindDN(username string, bind_pattern string) string {
	return fmt.Sprintf(bind_pattern, username)
}

func (pa *PasswordAuthenticator) updateOrDeletePasswordHash(valid bool, username string, password []byte) error {
	if valid {
		hash, err := authutil.Argon2MakeNewHash(password)
		if err != nil {
			if pa.logger != nil {
				pa.logger.Debugf(0, "Failure making new hash for password for user %s", username)
			}
			return nil
		}
		pa.cachedCredentials[username] = cacheCredentialEntry{
			Hash:       hash,
			Expiration: time.Now().Add(pa.expirationDuration)}

	} else {
		cachedCred, ok := pa.cachedCredentials[username]
		if ok {
			err := authutil.Argon2CompareHashAndPassword(cachedCred.Hash, password)
			if err == nil {
				delete(pa.cachedCredentials, username)
			}
		}
	}
	return nil
}

func (pa *PasswordAuthenticator) passwordAuthenticate(username string,
	password []byte) (valid bool, err error) {
	valid = false
	for _, u := range pa.ldapURL {
		for _, bindPattern := range pa.bindPattern {
			bindDN := convertToBindDN(username, bindPattern)
			valid, err = authutil.CheckLDAPUserPassword(*u, bindDN, string(password), pa.timeoutSecs, pa.rootCAs)
			if err != nil {
				if pa.logger != nil {
					pa.logger.Debugf(1, "Error checking LDAP user password url= %s", u)
				}
				continue
			}
			err = pa.updateOrDeletePasswordHash(valid, username, password)
			if err != nil && pa.logger != nil {
				pa.logger.Debugf(0, "Updating local password hash for user %s", username)
			}
			return valid, nil

		}
	}
	cachedCred, ok := pa.cachedCredentials[username]
	if ok {
		//Check validity
		err = authutil.Argon2CompareHashAndPassword(cachedCred.Hash, password)
		if err == nil {
			if cachedCred.Expiration.Sub(time.Now()) > 0 {
				return true, nil
			}
		}
	}
	return false, nil
}
