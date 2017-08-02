package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"

	// client side (interface with hardware)
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
	// server side:
	"github.com/tstranex/u2f"

	"github.com/Symantec/keymaster/lib/webapi/v0/proto"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultKeysLocation = "/.ssh/"
const RSAKeySize = 2048
const FilePrefix = "keymaster"

const ClientDataAuthenticationTypeValue = "navigator.id.getAssertion"

type baseConfig struct {
	Gen_Cert_URLS string
	//UserAuth          string
}

type AppConfigFile struct {
	Base baseConfig
}

var (
	Version        = "No version provided"
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
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
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
		return nil, err
	}
	// When using a file this used to be: fh, err := os.Open(pubKeyFilename)
	fh := strings.NewReader(filedata)

	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		return nil, err
	}

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	req, err := http.NewRequest(method, urlStr, bodyBuf)
	if err != nil {
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
	// Add the login cookies
	for _, cookie := range authCookies {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req) // Client.Get(targetUrl)
	if err != nil {
		log.Printf("Failure to do x509 req %s", err)
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("got error from call %s, url='%s'\n", resp.Status, url)
		return nil, err
	}
	return ioutil.ReadAll(resp.Body)

}

func doU2FAuthenticate(client *http.Client, authCookies []*http.Cookie, baseURL string) error {
	log.Printf("top of doU2fAuthenticate")
	url := baseURL + "/u2f/SignRequest"
	signRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	// Add the login cookies
	for _, cookie := range authCookies {
		signRequest.AddCookie(cookie)
	}
	signRequestResp, err := client.Do(signRequest) // Client.Get(targetUrl)
	if err != nil {
		log.Printf("Failure to sign request req %s", err)
		return err
	}

	defer signRequestResp.Body.Close()
	if signRequestResp.StatusCode != 200 {
		log.Printf("got error from call %s, url='%s'\n", signRequestResp.Status, url)
		return err
	}

	var webSignRequest u2f.WebSignRequest
	if err := json.NewDecoder(signRequestResp.Body).Decode(&webSignRequest); err != nil {
		//http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		//        return
		log.Fatal(err)
	}

	// TODO: move this to initialization code, ans pass the device list to this function?
	// or maybe pass the token?...
	devices, err := u2fhid.Devices()
	if err != nil {
		log.Fatal(err)
	}
	if len(devices) == 0 {
		log.Fatal("no U2F tokens found")
	}

	// TODO: transform this into an iteration over all found devices
	d := devices[0]
	log.Printf("manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x", d.Manufacturer, d.Product, d.ProductID, d.VendorID)

	dev, err := u2fhid.Open(d)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()
	t := u2ftoken.NewToken(dev)

	// This section of version could be if *debug
	version, err := t.Version()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("version:", version)

	///////
	tokenAuthenticationClientData := u2f.ClientData{Typ: ClientDataAuthenticationTypeValue, Challenge: webSignRequest.Challenge, Origin: webSignRequest.AppID}
	tokenAuthenticationBuf := new(bytes.Buffer)
	err = json.NewEncoder(tokenAuthenticationBuf).Encode(tokenAuthenticationClientData)
	if err != nil {
		log.Fatal(err)
	}
	reqSignChallenge := sha256.Sum256(tokenAuthenticationBuf.Bytes())

	challenge := make([]byte, 32)
	app := make([]byte, 32)

	challenge = reqSignChallenge[:]
	reqSingApp := sha256.Sum256([]byte(webSignRequest.AppID))
	app = reqSingApp[:]

	// We find out what key is associated to the currently inserted device.
	keyIsKnown := false
	var req u2ftoken.AuthenticateRequest
	var keyHandle []byte
	for _, registeredKey := range webSignRequest.RegisteredKeys {
		decodedHandle, err := base64.RawURLEncoding.DecodeString(registeredKey.KeyHandle)
		if err != nil {
			log.Fatal(err)
		}
		keyHandle = decodedHandle

		req = u2ftoken.AuthenticateRequest{
			Challenge:   challenge,
			Application: app,
			KeyHandle:   keyHandle,
		}

		//log.Printf("%+v", req)
		if err := t.CheckAuthenticate(req); err == nil {
			keyIsKnown = true
			break
		}
	}
	if !keyIsKnown {
		err = errors.New("key is not known")
		return err
	}

	// Now we ask the token to sign/authenticate
	log.Println("authenticating, provide user presence")
	var rawBytes []byte
	for {
		res, err := t.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			log.Fatal(err)
		}
		rawBytes = res.RawResponse
		log.Printf("counter = %d, signature = %x", res.Counter, res.Signature)
		break
	}

	// now we do the last request
	var signRequestResponse u2f.SignResponse
	signRequestResponse.KeyHandle = base64.RawURLEncoding.EncodeToString(keyHandle)
	signRequestResponse.SignatureData = base64.RawURLEncoding.EncodeToString(rawBytes)
	signRequestResponse.ClientData = base64.RawURLEncoding.EncodeToString(tokenAuthenticationBuf.Bytes())

	//
	webSignRequestBuf := &bytes.Buffer{}
	err = json.NewEncoder(webSignRequestBuf).Encode(signRequestResponse)
	if err != nil {
		log.Fatal(err)
	}

	url = baseURL + "/u2f/SignResponse"
	webSignRequest2, err := http.NewRequest("POST", url, webSignRequestBuf)
	// Add the login cookies
	for _, cookie := range authCookies {
		webSignRequest2.AddCookie(cookie)
	}
	signRequestResp2, err := client.Do(webSignRequest2) // Client.Get(targetUrl)
	if err != nil {
		log.Printf("Failure to sign request req %s", err)
		return err
	}

	defer signRequestResp2.Body.Close()
	if signRequestResp2.StatusCode != 200 {
		log.Printf("got error from call %s, url='%s'\n", signRequestResp2.Status, url)
		return err
	}

	return nil
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

func getCertsFromServer(signer crypto.Signer, userName string, password []byte, baseUrl string, tlsConfig *tls.Config, skipu2f bool) (sshCert []byte, x509Cert []byte, err error) {
	//First Do Login

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

	loginUrl := baseUrl + proto.LoginPath
	form := url.Values{}
	form.Add("username", userName)
	form.Add("password", string(password[:]))
	req, err := http.NewRequest("POST", loginUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	loginResp, err := client.Do(req) //client.Get(targetUrl)
	if err != nil {
		log.Printf("got error from req")
		log.Println(err)
		// TODO: differentiate between 400 and 500 errors
		// is OK to fail.. try next
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

	loginJSONResponse := proto.LoginResponse{}
	//body := jsonrr.Result().Body
	err = json.NewDecoder(loginResp.Body).Decode(&loginJSONResponse)
	if err != nil {
		return nil, nil, err
	}
	loginResp.Body.Close() //so that we can reuse the channel

	for _, backend := range loginJSONResponse.CertAuthBackend {
		if backend == proto.AuthTypePassword {
			skipu2f = true
		}
	}
	// upgrade to u2f
	if !skipu2f {
		err = doU2FAuthenticate(client, loginResp.Cookies(), baseUrl)
		if err != nil {

			return nil, nil, err
		}
	}
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

	return sshCert, x509Cert, nil
}

func getCertFromTargetUrls(signer crypto.Signer, userName string, password []byte, targetUrls []string, rootCAs *x509.CertPool, skipu2f bool) (sshCert []byte, x509Cert []byte, err error) {
	success := false
	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}

	for _, baseUrl := range targetUrls {
		log.Printf("attempting to target '%s' for '%s'\n", baseUrl, userName)
		sshCert, x509Cert, err = getCertsFromServer(signer, userName, password, baseUrl, tlsConfig, skipu2f)
		if err != nil {
			log.Println(err)
			continue
		}
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

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
}

func main() {
	flag.Usage = Usage
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
	privateKeyPath := filepath.Join(homeDir, commonCertPath, FilePrefix)
	signer, _, err := genKeyPair(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	sshCert, x509Cert, err := getCertFromTargetUrls(signer, userName,
		password, strings.Split(config.Base.Gen_Cert_URLS, ","), nil, false)
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
