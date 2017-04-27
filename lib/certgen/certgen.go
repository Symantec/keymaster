/*
  Package certgen id set of utilities used to generate ssh certificates
*/
package certgen

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/ssh"
	"math/big"
	//"os"
	"os/exec"
	"time"

	"fmt"
)

const numValidHours = 24

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

func goCertToFileString(c ssh.Certificate, username string) (string, error) {
	certBytes := c.Marshal()
	encoded := base64.StdEncoding.EncodeToString(certBytes)
	fileComment := "/tmp/" + username + "-cert.pub"
	return "ssh-rsa-cert-v01@openssh.com " + encoded + " " + fileComment, nil
}

// gen_user_cert a username and key, returns a short lived cert for that user
func GenSSHCertFileString(username string, userPubKey string, signer ssh.Signer, host_identity string) (string, error) {
	//const numValidHours = 24

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

func GenSSHCertFileStringFromSSSDPublicKey(userName string, signer ssh.Signer, hostIdentity string) (string, error) {

	userPubKey, err := GetUserPubKeyFromSSSD(userName)
	if err != nil {
		return "", err
	}
	cert, err := GenSSHCertFileString(userName, userPubKey, signer, hostIdentity)
	if err != nil {
		return "", err
	}
	return cert, err
}

/// X509 section

func getPubKeyFromPem(pubkey string) (pub interface{}, err error) {
	block, rest := pem.Decode([]byte(pubkey))
	if block == nil || block.Type != "PUBLIC KEY" {
		err := errors.New(fmt.Sprintf("Cannot decode user public Key '%s' rest='%s'", pubkey, string(rest)))
		if block != nil {
			err = errors.New(fmt.Sprintf("public key bad type %s", block.Type))
		}
		return "", err
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func getPrivateKeyFromPem(privateKey string) (pub interface{}, err error) {
	//TODO handle ecdsa and other non-rsa keys
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		err := errors.New("Cannot decode Private Key")
		return "", err
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		err := errors.New("Cannot process that key")
		return pub, err
	}
}

// returns an x509 cert that is with the username in the common name
func Genx509SCert(userName string, userPub interface{}, caCertString string, caPriv interface{}) (string, error) {

	caCertBlock, _ := pem.Decode([]byte(caCertString))
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		err := errors.New("Cannot decode ca cert")
		return "", err
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return "", err
	}

	//// Now do the actual work...
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(numValidHours) * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		//log.Fatalf("failed to generate serial number: %s", err)
		return "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   userName,
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		//ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		//BasicConstraintsValid: true,
		IsCA: false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, userPub, caPriv)
	if err != nil {

		//log.Fatalf("Failed to create certificate: %s", err)
		return "", err
	}
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))

	return pemCert, nil
}
