package util

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/Symantec/Dominator/lib/log"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"
)

const rsaKeySize = 2048

func getUserCreds(userName string) (password []byte, err error) {
	fmt.Printf("Password for %s: ", userName)
	password, err = gopass.GetPasswd()
	if err != nil {
		return nil, err
		// Handle gopass.ErrInterrupted or getch() read error
	}
	return password, nil
}

func genKeyPair(
	privateKeyPath string, identity string, logger log.Logger) (
	crypto.Signer, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, "", err
	}
	// privateKeyPath := BasePath + prefix
	pubKeyPath := privateKeyPath + ".pub"

	err = ioutil.WriteFile(
		privateKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}),
		0600)
	if err != nil {
		logger.Printf("Failed to save privkey")
		return nil, "", err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", err
	}
	marshaledPubKeyBytes := ssh.MarshalAuthorizedKey(pub)
	marshaledPubKeyBytes = bytes.TrimRight(marshaledPubKeyBytes, "\r\n")
	var pubKeyBuffer bytes.Buffer
	_, err = pubKeyBuffer.Write(marshaledPubKeyBytes)
	if err != nil {
		return nil, "", err
	}
	_, err = pubKeyBuffer.Write([]byte(" " + identity + "\n"))
	if err != nil {
		return nil, "", err
	}
	return privateKey, pubKeyPath, ioutil.WriteFile(pubKeyPath, pubKeyBuffer.Bytes(), 0644)
}

func getHttpClient(tlsConfig *tls.Config) (*http.Client, error) {
	clientTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// proxy env variables in ascending order of preference, lower case 'http_proxy' dominates
	// just like curl
	proxyEnvVariables := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy"}
	for _, proxyVar := range proxyEnvVariables {
		httpProxy, err := getParseURLEnvVariable(proxyVar)
		if err == nil && httpProxy != nil {
			clientTransport.Proxy = http.ProxyURL(httpProxy)
		}
	}

	// TODO: change timeout const for a flag
	client := &http.Client{Transport: clientTransport, Timeout: 5 * time.Second}
	return client, nil
}

func getParseURLEnvVariable(name string) (*url.URL, error) {
	envVariable := os.Getenv(name)
	if len(envVariable) < 1 {
		return nil, nil
	}
	envUrl, err := url.Parse(envVariable)
	if err != nil {
		return nil, err
	}

	return envUrl, nil
}
