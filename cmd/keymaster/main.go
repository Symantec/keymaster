package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/Dominator/lib/log/cmdlogger"

	// client side (interface with hardware)
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
	// server side:
	"github.com/tstranex/u2f"

	"github.com/Symantec/keymaster/lib/client/config"
	"github.com/Symantec/keymaster/lib/client/util"
	"github.com/Symantec/keymaster/lib/webapi/v0/proto"

	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultKeysLocation = "/.ssh/"
const FilePrefix = "keymaster"

const ClientDataAuthenticationTypeValue = "navigator.id.getAssertion"

var (
	// Must be a global variable in the data segment so that the build
	// process can inject the version number on the fly when building the
	// binary. Use only from the Usage() function.
	Version = "No version provided"
)

var (
	configFilename = flag.String("config", filepath.Join(os.Getenv("HOME"), ".keymaster", "client_config.yml"), "The filename of the configuration")
	rootCAFilename = flag.String("rootCAFilename", "", "(optional) name for using non OS root CA to verify TLS connections")
	configHost     = flag.String("configHost", "", "Get a bootstrap config from this host")
	cliUsername    = flag.String("username", "", "username for keymaster")
	duration       = flag.String("duration", "16h", "Duration of the requested certificates in golang duration format (ex: 30s, 5m, 12h)")
	checkDevices   = flag.Bool("checkDevices", false, "CheckU2F devices in your system")
	noU2F          = flag.Bool("noU2F", false, "Don't use U2F as second factor")
	noVIPAccess    = flag.Bool("noVIPAccess", false, "Don't use VIPAccess as second factor")
)

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

	err = bodyWriter.WriteField("duration", *duration)
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

func doCertRequest(client *http.Client, authCookies []*http.Cookie, url, filedata string, logger log.Logger) ([]byte, error) {

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
		logger.Printf("Failure to do x509 req %s", err)
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logger.Printf("got error from call %s, url='%s'\n", resp.Status, url)
		return nil, err
	}
	return ioutil.ReadAll(resp.Body)

}

func checkU2FDevices(logger log.Logger) {
	// TODO: move this to initialization code, ans pass the device list to this function?
	// or maybe pass the token?...
	devices, err := u2fhid.Devices()
	if err != nil {
		logger.Fatal(err)
	}
	if len(devices) == 0 {
		logger.Fatal("no U2F tokens found")
	}

	// TODO: transform this into an iteration over all found devices
	for _, d := range devices {
		//d := devices[0]
		logger.Printf("manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x", d.Manufacturer, d.Product, d.ProductID, d.VendorID)

		dev, err := u2fhid.Open(d)
		if err != nil {
			logger.Fatal(err)
		}
		defer dev.Close()
	}

}

func doU2FAuthenticate(
	client *http.Client,
	authCookies []*http.Cookie,
	baseURL string,
	logger log.DebugLogger) error {
	logger.Printf("top of doU2fAuthenticate")
	url := baseURL + "/u2f/SignRequest"
	signRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logger.Fatal(err)
	}
	// Add the login cookies
	for _, cookie := range authCookies {
		signRequest.AddCookie(cookie)
	}
	logger.Debugf(0, "Authcookies:  %+v", authCookies)

	signRequestResp, err := client.Do(signRequest) // Client.Get(targetUrl)
	if err != nil {
		logger.Printf("Failure to sign request req %s", err)
		return err
	}
	logger.Debugf(0, "Get url request did not failed %+v", signRequestResp)

	// Dont defer the body response Close ... as we need to close it explicitly
	// in the body of the function so that we can reuse the connection
	if signRequestResp.StatusCode != 200 {
		signRequestResp.Body.Close()
		logger.Printf("got error from call %s, url='%s'\n", signRequestResp.Status, url)
		err = errors.New("failed respose from sign request")
		return err
	}

	var webSignRequest u2f.WebSignRequest
	if err := json.NewDecoder(signRequestResp.Body).Decode(&webSignRequest); err != nil {
		//http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		//        return
		logger.Fatal(err)
	}
	io.Copy(ioutil.Discard, signRequestResp.Body)
	signRequestResp.Body.Close()

	// TODO: move this to initialization code, ans pass the device list to this function?
	// or maybe pass the token?...
	devices, err := u2fhid.Devices()
	if err != nil {
		logger.Fatal(err)
		return err
	}
	if len(devices) == 0 {
		err = errors.New("no U2F tokens found")
		logger.Println(err)
		return err
	}

	// TODO: transform this into an iteration over all found devices
	d := devices[0]
	logger.Printf("manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x", d.Manufacturer, d.Product, d.ProductID, d.VendorID)

	dev, err := u2fhid.Open(d)
	if err != nil {
		logger.Fatal(err)
	}
	defer dev.Close()
	t := u2ftoken.NewToken(dev)

	version, err := t.Version()
	if err != nil {
		logger.Fatal(err)
	}
	// TODO: Maybe use Debugf()?
	logger.Println("version:", version)

	///////
	tokenAuthenticationClientData := u2f.ClientData{Typ: ClientDataAuthenticationTypeValue, Challenge: webSignRequest.Challenge, Origin: webSignRequest.AppID}
	tokenAuthenticationBuf := new(bytes.Buffer)
	err = json.NewEncoder(tokenAuthenticationBuf).Encode(tokenAuthenticationClientData)
	if err != nil {
		logger.Fatal(err)
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
			logger.Fatal(err)
		}
		keyHandle = decodedHandle

		req = u2ftoken.AuthenticateRequest{
			Challenge:   challenge,
			Application: app,
			KeyHandle:   keyHandle,
		}

		//logger.Printf("%+v", req)
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
	logger.Println("authenticating, provide user presence")
	var rawBytes []byte
	for {
		res, err := t.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			logger.Fatal(err)
		}
		rawBytes = res.RawResponse
		logger.Printf("counter = %d, signature = %x", res.Counter, res.Signature)
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
		logger.Fatal(err)
	}

	url = baseURL + "/u2f/SignResponse"
	webSignRequest2, err := http.NewRequest("POST", url, webSignRequestBuf)
	// Add the login cookies
	for _, cookie := range authCookies {
		webSignRequest2.AddCookie(cookie)
	}
	signRequestResp2, err := client.Do(webSignRequest2) // Client.Get(targetUrl)
	if err != nil {
		logger.Printf("Failure to sign request req %s", err)
		return err
	}

	defer signRequestResp2.Body.Close()
	if signRequestResp2.StatusCode != 200 {
		logger.Printf("got error from call %s, url='%s'\n", signRequestResp2.Status, url)
		return err
	}
	io.Copy(ioutil.Discard, signRequestResp2.Body)
	return nil
}

func doVIPAuthenticate(
	client *http.Client,
	authCookies []*http.Cookie,
	baseURL string,
	logger log.DebugLogger) error {
	logger.Printf("top of doVIPAuthenticate")

	// Read VIP token from client

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter VIP/OTP code: ")
	otpText, err := reader.ReadString('\n')
	otpText = strings.TrimSpace(otpText)
	//fmt.Println(codeText)
	logger.Debugf(1, "codeText:  '%s'", otpText)

	// TODO: add some client side validation that the codeText is actually a six digit
	// integer

	VIPLoginURL := baseURL + "/api/v0/vipAuth"

	form := url.Values{}
	form.Add("OTP", otpText)
	//form.Add("password", string(password[:]))
	req, err := http.NewRequest("POST", VIPLoginURL, strings.NewReader(form.Encode()))

	// Add the login cookies
	for _, cookie := range authCookies {
		req.AddCookie(cookie)
	}
	logger.Debugf(0, "Authcookies:  %+v", authCookies)

	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	loginResp, err := client.Do(req) //client.Get(targetUrl)
	if err != nil {
		logger.Printf("got error from req")
		logger.Println(err)
		// TODO: differentiate between 400 and 500 errors
		// is OK to fail.. try next
		return err
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != 200 {
		logger.Printf("got error from login call %s", loginResp.Status)
		return err
	}

	loginJSONResponse := proto.LoginResponse{}
	//body := jsonrr.Result().Body
	err = json.NewDecoder(loginResp.Body).Decode(&loginJSONResponse)
	if err != nil {
		return err
	}
	io.Copy(ioutil.Discard, loginResp.Body)

	logger.Debugf(1, "This the login response=%v\n", loginJSONResponse)

	return nil
}

func getCertsFromServer(
	signer crypto.Signer,
	userName string,
	password []byte,
	baseUrl string,
	tlsConfig *tls.Config,
	skip2fa bool,
	logger log.DebugLogger) (sshCert []byte, x509Cert []byte, err error) {
	//First Do Login
	client, err := util.GetHttpClient(tlsConfig)
	if err != nil {
		return nil, nil, err
	}

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
		logger.Printf("got error from req")
		logger.Println(err)
		// TODO: differentiate between 400 and 500 errors
		// is OK to fail.. try next
		return nil, nil, err
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != 200 {
		logger.Printf("got error from login call %s", loginResp.Status)
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

	logger.Debugf(1, "This the login response=%v\n", loginJSONResponse)

	allowVIP := false
	allowU2F := false
	for _, backend := range loginJSONResponse.CertAuthBackend {
		if backend == proto.AuthTypePassword {
			skip2fa = true
		}
		if backend == proto.AuthTypeSymantecVIP {
			allowVIP = true
			//remote next statemente later
			//skipu2f = true
		}
		if backend == proto.AuthTypeU2F {
			allowU2F = true
		}
	}

	// Dont try U2F if chosen by user
	if *noU2F {
		allowU2F = false
	}
	if *noVIPAccess {
		allowVIP = false
	}

	// upgrade to u2f
	successful2fa := false
	if !skip2fa {
		if allowU2F {
			devices, err := u2fhid.Devices()
			if err != nil {
				logger.Fatal(err)
				return nil, nil, err
			}
			if len(devices) > 0 {

				err = doU2FAuthenticate(
					client, loginResp.Cookies(), baseUrl, logger)
				if err != nil {

					return nil, nil, err
				}
				successful2fa = true
			}
		}

		if allowVIP && !successful2fa {
			err = doVIPAuthenticate(
				client, loginResp.Cookies(), baseUrl, logger)
			if err != nil {

				return nil, nil, err
			}
			successful2fa = true
		}

		if !successful2fa {
			err = errors.New("Failed to Pefrom 2FA (as requested from server)")
			return nil, nil, err
		}

	}

	logger.Debugf(1, "Authentication Phase complete")

	//now get x509 cert
	pubKey := signer.Public()
	derKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, err
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derKey}))

	// TODO: urlencode the userName
	x509Cert, err = doCertRequest(
		client,
		loginResp.Cookies(),
		baseUrl+"/certgen/"+userName+"?type=x509",
		pemKey,
		logger)
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
	sshCert, err = doCertRequest(
		client,
		loginResp.Cookies(),
		baseUrl+"/certgen/"+userName+"?type=ssh",
		sshAuthFile,
		logger)
	if err != nil {
		return nil, nil, err
	}

	return sshCert, x509Cert, nil
}

func getCertFromTargetUrls(
	signer crypto.Signer,
	userName string,
	password []byte,
	targetUrls []string,
	rootCAs *x509.CertPool,
	skipu2f bool,
	logger log.DebugLogger) (sshCert []byte, x509Cert []byte, err error) {
	success := false
	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}

	for _, baseUrl := range targetUrls {
		logger.Printf("attempting to target '%s' for '%s'\n", baseUrl, userName)
		sshCert, x509Cert, err = getCertsFromServer(
			signer, userName, password, baseUrl, tlsConfig, skipu2f, logger)
		if err != nil {
			logger.Println(err)
			continue
		}
		success = true
		break

	}
	if !success {
		err := errors.New("Failed to get creds")
		return nil, nil, err
	}

	return sshCert, x509Cert, nil
}

func Usage() {
	fmt.Fprintf(
		os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
}

func main() {
	flag.Usage = Usage
	flag.Parse()
	logger := cmdlogger.New()

	if *checkDevices {
		checkU2FDevices(logger)
		return
	}

	var rootCAs *x509.CertPool
	if len(*rootCAFilename) > 1 {
		caData, err := ioutil.ReadFile(*rootCAFilename)
		if err != nil {
			logger.Printf("Failed to read caFilename")
			logger.Fatal(err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caData) {
			logger.Fatal("cannot append file data")
		}

	}
	//ensure duration is sane
	parsedDuration, err := time.ParseDuration(*duration)
	if err != nil {
		logger.Printf("Duration cannot be parsed, please check syntax I read '%s'", *duration)
		logger.Fatal(err)
	}

	usr, err := user.Current()
	if err != nil {
		logger.Printf("cannot get current user info")
		logger.Fatal(err)
	}
	userName := usr.Username

	homeDir, err := util.GetUserHomeDir(usr)
	if err != nil {
		logger.Fatal(err)
	}

	configPath, _ := filepath.Split(*configFilename)

	err = os.MkdirAll(configPath, 0755)
	if err != nil {
		logger.Fatal(err)
	}

	if len(*configHost) > 1 {
		err = config.GetConfigFromHost(*configFilename, *configHost, rootCAs, logger)
		if err != nil {
			logger.Fatal(err)
		}
	} else if len(defaultConfigHost) > 1 { // if there is a configHost AND there is NO config file, create one
		if _, err := os.Stat(*configFilename); os.IsNotExist(err) {
			err = config.GetConfigFromHost(
				*configFilename, defaultConfigHost, rootCAs, logger)
			if err != nil {
				logger.Fatal(err)
			}
		}
	}

	config, err := config.LoadVerifyConfigFile(*configFilename)
	if err != nil {
		logger.Fatal(err)
	}

	if len(config.Base.Username) > 0 {
		userName = config.Base.Username
	}
	// command line always wins over pref or config
	if *cliUsername != "" {
		userName = *cliUsername
	}

	//sshPath := homeDir + "/.ssh/"
	privateKeyPath := filepath.Join(homeDir, DefaultKeysLocation, FilePrefix)
	sshConfigPath, _ := filepath.Split(privateKeyPath)
	err = os.MkdirAll(sshConfigPath, 0700)
	if err != nil {
		logger.Fatal(err)
	}

	tempPrivateKeyPath := filepath.Join(homeDir, DefaultKeysLocation, "keymaster-temp")
	signer, tempPublicKeyPath, err := util.GenKeyPair(
		tempPrivateKeyPath, userName+"@keymaster", logger)
	if err != nil {
		logger.Fatal(err)
	}
	defer os.Remove(tempPrivateKeyPath)
	defer os.Remove(tempPublicKeyPath)

	password, err := util.GetUserCreds(userName)
	if err != nil {
		logger.Fatal(err)
	}

	sshCert, x509Cert, err := getCertFromTargetUrls(
		signer,
		userName,
		password,
		strings.Split(config.Base.Gen_Cert_URLS, ","),
		rootCAs,
		false,
		logger)
	if err != nil {
		logger.Fatal(err)
	}
	if sshCert == nil || x509Cert == nil {
		err := errors.New("Could not get cert from any url")
		logger.Fatal(err)
	}
	logger.Debugf(0, "Got Certs from server")
	//..
	if _, ok := os.LookupEnv("SSH_AUTH_SOCK"); ok {
		// TODO(rgooch): Parse certificate to get actual lifetime.
		cmd := exec.Command("ssh-add", "-d", privateKeyPath)
		cmd.Run()
	}

	//rename files to expected paths
	err = os.Rename(tempPrivateKeyPath, privateKeyPath)
	if err != nil {
		err := errors.New("Could not rename private Key")
		logger.Fatal(err)
	}

	err = os.Rename(tempPublicKeyPath, privateKeyPath+".pub")
	if err != nil {
		err := errors.New("Could not rename public Key")
		logger.Fatal(err)
	}

	// now we write the cert file...
	sshCertPath := privateKeyPath + "-cert.pub"
	err = ioutil.WriteFile(sshCertPath, sshCert, 0644)
	if err != nil {
		err := errors.New("Could not write ssh cert")
		logger.Fatal(err)
	}
	x509CertPath := privateKeyPath + "-x509Cert.pem"
	err = ioutil.WriteFile(x509CertPath, x509Cert, 0644)
	if err != nil {
		err := errors.New("Could not write ssh cert")
		logger.Fatal(err)
	}

	logger.Printf("Success")
	if _, ok := os.LookupEnv("SSH_AUTH_SOCK"); ok {
		// TODO(rgooch): Parse certificate to get actual lifetime.
		lifetime := fmt.Sprintf("%ds", uint64(parsedDuration.Seconds()))
		cmd := exec.Command("ssh-add", "-t", lifetime, privateKeyPath)
		cmd.Run()
	}
}
