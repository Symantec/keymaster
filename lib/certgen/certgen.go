/*
  Package certgen id set of utilities used to generate ssh certificates
*/
package certgen

import (
	"bytes"
	"encoding/base64"
	"golang.org/x/crypto/ssh"
	"os"
	"os/exec"
	"time"
)

// GetUserPubKeyFromSSSD user authorized keys content based on the running sssd configuration
func GetUserPubKeyFromSSSD(username string) (string, error) {
	cmd := exec.Command("/usr/bin/sss_ssh_authorizedkeys", username)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

func signUserPubKey(username string, userPubKey string, signer ssh.Signer) (string, error) {
	hostIdentity, err := getHostIdentity()
	if err != nil {
		return "", err
	}
	return GenSSHCertFileString(username, userPubKey, signer, hostIdentity)
}

func goCertToFileString(c ssh.Certificate, username string) (string, error) {
	certBytes := c.Marshal()
	encoded := base64.StdEncoding.EncodeToString(certBytes)
	fileComment := "/tmp/" + username + "-cert.pub"
	return "ssh-rsa-cert-v01@openssh.com " + encoded + " " + fileComment, nil
}

// gen_user_cert a username and key, returns a short lived cert for that user
func GenSSHCertFileString(username string, userPubKey string, signer ssh.Signer, host_identity string) (string, error) {
	const numValidHours = 24

	userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(userPubKey))
	if err != nil {
		return "", err
	}
	keyIdentity := host_identity + "_" + username

	currentEpoch := uint64(time.Now().Unix())
	expireEpoch := currentEpoch + (3600 * numValidHours)

	// The values of the permissions are taken from the default values used
	// by ssh-keygen
	cert := ssh.Certificate{
		Key:             userKey,
		CertType:        ssh.UserCert,
		SignatureKey:    signer.PublicKey(),
		ValidPrincipals: []string{username},
		KeyId:           keyIdentity,
		ValidAfter:      currentEpoch,
		ValidBefore:     expireEpoch,
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"permit-X11-forwarding":   "",
			"permit-agent-forwarding": "",
			"permit-port-forwarding":  "",
			"permit-pty":              "",
			"permit-user-rc":          ""}}}

	err = cert.SignCert(bytes.NewReader(cert.Marshal()), signer)
	if err != nil {
		return "", err
	}
	certString, err := goCertToFileString(cert, username)
	if err != nil {
		return "", err
	}
	return certString, nil
}

func getHostIdentity() (string, error) {
	return os.Hostname()
}

func genUserCert(userName string, signer ssh.Signer) (string, error) {

	userPubKey, err := GetUserPubKeyFromSSSD(userName)
	if err != nil {
		return "", err
	}

	cert, err := signUserPubKey(userName, userPubKey, signer)
	if err != nil {
		return "", err
	}
	return cert, err
}
