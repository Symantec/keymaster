package authutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/foomo/htpasswd"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/ldap.v2"
)

func CheckHtpasswdUserPassword(username string, password string, htpasswdBytes []byte) (bool, error) {
	//	secrets := HtdigestFileProvider(htpasswdFilename)
	passwords, err := htpasswd.ParseHtpasswd(htpasswdBytes)
	if err != nil {
		return false, err
	}
	hash, ok := passwords[username]
	if !ok {
		return false, nil
	}
	// only understand bcrypt
	if !strings.HasPrefix(hash, "$2y$") {
		err := errors.New("Can only use bcrypt for htpasswd")
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false, nil
	}
	return true, nil

}

func CheckLDAPUserPassword(u url.URL, bindDN string, bindPassword string, timeoutSecs uint, rootCAs *x509.CertPool) (bool, error) {
	if u.Scheme != "ldaps" {
		err := errors.New("Invalid ldap scheme (we only support ldaps")
		return false, err
	}
	//hostnamePort := server + ":636"
	serverPort := strings.Split(u.Host, ":")
	port := "636"
	if len(serverPort) == 2 {
		port = serverPort[1]
	}
	server := serverPort[0]
	hostnamePort := server + ":" + port

	timeout := time.Duration(time.Duration(timeoutSecs) * time.Second)
	start := time.Now()
	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", hostnamePort,
		&tls.Config{ServerName: server, RootCAs: rootCAs})
	if err != nil {
		errorTime := time.Since(start).Seconds() * 1000
		log.Printf("connction failure for:%s (%s)(time(ms)=%v)", server, err.Error(), errorTime)
		return false, err
	}

	// we dont close the tls connection directly  close defer to the new ldap connection
	conn := ldap.NewConn(tlsConn, true)
	defer conn.Close()

	//connectionTime := time.Since(start).Seconds() * 1000

	conn.SetTimeout(timeout)
	conn.Start()
	err = conn.Bind(bindDN, bindPassword)
	if err != nil {
		log.Printf("Bind failure for server:%s bindDN:'%s' (%s)", server, bindDN, err.Error())
		if strings.Contains(err.Error(), "Invalid Credentials") {
			return false, nil
		}
		return false, err
	}
	return true, nil

}

func ParseLDAPURL(ldapUrl string) (*url.URL, error) {
	u, err := url.Parse(ldapUrl)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ldaps" {
		err := errors.New("Invalid ldap scheme (we only support ldaps")
		return nil, err
	}
	//extract port if any... and if NIL then set it to 636
	return u, nil
}
