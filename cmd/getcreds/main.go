package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

const DEFAULT_KEYS_LOCATION = "/.ssh/"
const RSA_KEY_SIZE = 2048
const FILE_PREFIX = "keymaster"

type baseConfig struct {
	Gen_Cert_URLS string
	//UserAuth          string
}

type AppConfigFile struct {
	Base baseConfig
}

var (
	configFilename = flag.String("config", "config.yml", "The filename of the configuration")
	debug          = flag.Bool("debug", false, "Enable debug messages to console")
)

func getUserHomeDir(usr *user.User) (string, error) {
	// TODO: verify on Windows... see: http://stackoverflow.com/questions/7922270/obtain-users-home-directory
	return usr.HomeDir, nil
}

// generateKeyPair uses internal golang functions to be portable
// mostly comes from: http://stackoverflow.com/questions/21151714/go-generate-an-ssh-public-key
func genKeyPair(privateKeyPath string) (crypto.Signer, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSA_KEY_SIZE)
	if err != nil {
		return nil, "", err
	}

	//privateKeyPath := BasePath + prefix
	pubKeyPath := privateKeyPath + ".pub"

	err = ioutil.WriteFile(
		privateKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}),
		0600)
	if err != nil {
		log.Printf("Failed to save privkey")
		return nil, "", err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return privateKey, pubKeyPath, ioutil.WriteFile(pubKeyPath, ssh.MarshalAuthorizedKey(pub), 0644)
}
func loadVerifyConfigFile(configFilename string) (AppConfigFile, error) {
	var config AppConfigFile
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return config, err
	}
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		//panic(err)
		err = errors.New("cannot read config file")
		return config, err
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		err = errors.New("Cannot parse config file")
		return config, err
	}

	if len(config.Base.Gen_Cert_URLS) < 1 {
		err = errors.New("Invalid Config file... no place get the certs")
		return config, err
	}
	// TODO: ensure all enpoints are https urls

	return config, nil
}

// This is now copy-paste from the server test side... probably make public and reuse.
func createKeyBodyRequest(method, urlStr, filedata string) (*http.Request, error) {
	//create attachment....
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	//
	fileWriter, err := bodyWriter.CreateFormFile("pubkeyfile", "somefilename.pub")
	if err != nil {
		fmt.Println("error writing to buffer")
		//t.Fatal(err)
		return nil, err
	}
	//when using a file this used to be: fh, err := os.Open(pubKeyFilename)
	fh := strings.NewReader(filedata)

	//iocopy
	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		//t.Fatal(err)
		return nil, err
	}

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest(method, urlStr, bodyBuf)
	if err != nil {
		//t.Fatal(err)
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	return req, nil
}

func doCertRequest(client *http.Client, authCookies []*http.Cookie, url, filedata string) ([]byte, error) {

	req, err := createKeyBodyRequest("POST", url, filedata)
	if err != nil {
		return nil, err
	}
	//add the login cookies
	for _, cookie := range authCookies {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req) //client.Get(targetUrl)
	if err != nil {
		log.Printf("Failure to do x509 req")
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("got error from call %s, url='%s'\n", resp.Status, url)
		return nil, err
	}
	return ioutil.ReadAll(resp.Body)

}

func getCertsFromServer(signer crypto.Signer, userName string, password []byte, baseUrl string, tlsConfig *tls.Config) (sshCert []byte, x509Cert []byte, err error) {
	//First Do Login

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(5) * time.Second}
	loginUrl := baseUrl + "/api/v0/login"
	req, err := http.NewRequest("POST", loginUrl, nil)
	if err != nil {
		// Maybe fatal instead?
		return nil, nil, err
	}
	req.SetBasicAuth(userName, string(password[:]))
	loginResp, err := client.Do(req) //client.Get(targetUrl)
	if err != nil {
		log.Printf("got error from req")
		log.Println(err)
		//TODO: differentialte between 400 and 500 errors
		//is OK to fail.. try next
		return nil, nil, err
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != 200 {
		log.Printf("got error from login call %s", loginResp.Status)
		return nil, nil, err
	}
	//Enusre we have at least one cookie
	if len(loginResp.Cookies()) < 1 {
		err = errors.New("No cookies from login")
		return nil, nil, err
	}
	loginResp.Body.Close() //so that we can reuse the channel

	//now get x509 cert
	pubKey := signer.Public()
	derKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, err
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derKey}))

	// TODO: urlencode the userName
	x509Cert, err = doCertRequest(client, loginResp.Cookies(), baseUrl+"/certgen/"+userName+"?type=x509", pemKey)
	if err != nil {
		return nil, nil, err
	}

	//// Now we do sshCert!
	// generate and write public key
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, nil, err
	}
	sshAuthFile := string(ssh.MarshalAuthorizedKey(sshPub))
	sshCert, err = doCertRequest(client, loginResp.Cookies(), baseUrl+"/certgen/"+userName+"?type=ssh", sshAuthFile)
	if err != nil {
		return nil, nil, err
	}
	//sshReq, err := createKeyBodyRequest("POST", baseUrl+"/certgen/username?type=ssh", sshAuthFile)

	return sshCert, x509Cert, nil
}

func getCertFromTargetUrls(signer crypto.Signer, userName string, password []byte, targetUrls []string, rootCAs *x509.CertPool) (sshCert []byte, x509Cert []byte, err error) {
	success := false
	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}

	for _, baseUrl := range targetUrls {
		//targetUrl := baseUrl + userName
		log.Printf("attempting to target '%s' for '%s'\n", baseUrl, userName)
		/*
		 */
		sshCert, x509Cert, err = getCertsFromServer(signer, userName, password, baseUrl, tlsConfig)
		if err != nil {
			log.Println(err)
			continue
		}
		//cert = sshCert
		// now save the file
		success = true
		break

	}
	if !success {
		log.Printf("failed to get creds")
		err := errors.New("Failed to get creds")
		return nil, nil, err
	}

	return sshCert, x509Cert, nil
}

func getUserInfoAndCreds() (usr *user.User, password []byte, err error) {
	usr, err = user.Current()
	if err != nil {
		log.Printf("cannot get current user info")
		return nil, nil, err
	}
	userName := usr.Username

	fmt.Printf("Password for %s: ", userName)
	password, err = gopass.GetPasswd()
	if err != nil {
		return nil, nil, err
		// Handle gopass.ErrInterrupted or getch() read error
	}
	return usr, password, nil
}

func main() {
	flag.Parse()

	config, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		panic(err)
	}
	usr, password, err := getUserInfoAndCreds()
	if err != nil {
		log.Fatal(err)
	}
	userName := usr.Username

	homeDir, err := getUserHomeDir(usr)
	if err != nil {
		log.Fatal(err)
	}

	//sshPath := homeDir + "/.ssh/"
	commonCertPath := "/.ssh/"
	privateKeyPath := filepath.Join(homeDir, commonCertPath, FILE_PREFIX)
	signer, _, err := genKeyPair(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	sshCert, x509Cert, err := getCertFromTargetUrls(signer, userName, password, strings.Split(config.Base.Gen_Cert_URLS, ","), nil)
	if err != nil {
		log.Fatal(err)
	}
	if sshCert == nil || x509Cert == nil {
		err := errors.New("Could not get cert from any url")
		log.Fatal(err)
	}
	if *debug {
		log.Printf("Got Certs from server")
		// now we write the cert file...
	}
	sshCertPath := privateKeyPath + "-cert.pub"
	err = ioutil.WriteFile(sshCertPath, sshCert, 0644)
	if err != nil {
		err := errors.New("Could not write ssh cert")
		log.Fatal(err)
	}
	x509CertPath := privateKeyPath + "-x509Cert.pem"
	err = ioutil.WriteFile(x509CertPath, x509Cert, 0644)
	if err != nil {
		err := errors.New("Could not write ssh cert")
		log.Fatal(err)
	}

	log.Printf("Success")

}
