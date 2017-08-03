package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	//	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/Dominator/lib/logbuf"
	"github.com/Symantec/keymaster/lib/authutil"
	"github.com/Symantec/keymaster/lib/certgen"
	"github.com/Symantec/keymaster/lib/webapi/v0/proto"
	"github.com/Symantec/tricorder/go/healthserver"
	"github.com/Symantec/tricorder/go/tricorder"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tstranex/u2f"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
	"html/template"
	//"io"
	"io/ioutil"
	stdlog "log"
	//"net"
	"net/http"
	//"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	AuthTypeNone     = 0
	AuthTypePassword = 1 << iota
	AuthTypeFederated
	AuthTypeU2F
)

type authInfo struct {
	ExpiresAt time.Time
	Username  string
	AuthType  int
}

type u2fAuthData struct {
	Enabled      bool
	CreatedAt    time.Time
	CreatorAddr  string
	Counter      uint32
	Name         string
	Registration *u2f.Registration
}

type userProfile struct {
	U2fAuthData           map[int64]*u2fAuthData
	RegistrationChallenge *u2f.Challenge
	U2fAuthChallenge      *u2f.Challenge
}

type pendingAuth2Request struct {
	ExpiresAt time.Time
	state     string
	ctx       context.Context
}

type RuntimeState struct {
	Config              AppConfigFile
	SSHCARawFileContent []byte
	Signer              crypto.Signer
	ClientCAPool        *x509.CertPool
	HostIdentity        string
	KerberosRealm       *string
	caCertDer           []byte
	authCookie          map[string]authInfo
	SignerIsReady       chan bool
	Mutex               sync.Mutex
	//userProfile         map[string]userProfile
	pendingOauth2  map[string]pendingAuth2Request
	storageRWMutex sync.RWMutex
	db             *sql.DB
	dbType         string
}

const redirectPath = "/auth/oauth2/callback"
const secsBetweenCleanup = 30

var (
	Version          = "No version provided"
	configFilename   = flag.String("config", "config.yml", "The filename of the configuration")
	debug            = flag.Bool("debug", false, "Enable debug messages to console")
	generateConfig   = flag.Bool("generateConfig", false, "Generate new valid configuration")
	u2fAppID         = "https://www.example.com:33443"
	u2fTrustedFacets = []string{}

	metricsMutex   = &sync.Mutex{}
	certGenCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "keymaster_certificate_issuance_counter",
			Help: "Keymaster certificate issuance counter.",
		},
		[]string{"username", "type"},
	)
	logger log.Logger
)

func getHostIdentity() (string, error) {
	return os.Hostname()
}

func exitsAndCanRead(fileName string, description string) ([]byte, error) {
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return nil, err
	}
	buffer, err := ioutil.ReadFile(fileName)
	if err != nil {
		err = errors.New("cannot read " + description + "file")
		return nil, err
	}
	return buffer, err
}

func getSignerFromPEMBytes(privateKey []byte) (crypto.Signer, error) {
	return certgen.GetSignerFromPEMBytes(privateKey)
}

// Assumes the runtime state signer has been loaded!
func generateCADer(state *RuntimeState, keySigner crypto.Signer) ([]byte, error) {
	organizationName := state.HostIdentity
	if state.KerberosRealm != nil {
		organizationName = *state.KerberosRealm
	}
	return certgen.GenSelfSignedCACert(state.HostIdentity, organizationName, keySigner)
}

func (state *RuntimeState) performStateCleanup(secsBetweenCleanup int) {
	for {
		state.Mutex.Lock()
		initAuthSize := len(state.authCookie)
		for key, authInfo := range state.authCookie {
			if authInfo.ExpiresAt.Before(time.Now()) {
				delete(state.authCookie, key)
			}
		}
		finalAuthSize := len(state.authCookie)

		//
		initPendingSize := len(state.pendingOauth2)
		for key, oauth2Pending := range state.pendingOauth2 {
			if oauth2Pending.ExpiresAt.Before(time.Now()) {
				delete(state.pendingOauth2, key)
			}
		}
		finalPendingSize := len(state.pendingOauth2)

		state.Mutex.Unlock()
		if *debug {
			logger.Printf("Auth Cookie sizes: before:(%d) after (%d)\n", initAuthSize, finalAuthSize)
			logger.Printf("Pending Cookie sizes: before(%d) after(%d)", initPendingSize, finalPendingSize)
		}
		time.Sleep(time.Duration(secsBetweenCleanup) * time.Second)
	}

}

func convertToBindDN(username string, bind_pattern string) string {
	return fmt.Sprintf(bind_pattern, username)
}

func checkUserPassword(username string, password string, config AppConfigFile) (bool, error) {
	//if username == "camilo_viecco1" && password == "pass" {
	//	return true, nil
	//}

	const timeoutSecs = 3
	bindDN := convertToBindDN(username, config.Ldap.Bind_Pattern)
	for _, ldapUrl := range strings.Split(config.Ldap.LDAP_Target_URLs, ",") {
		if len(ldapUrl) < 1 {
			continue
		}
		u, err := authutil.ParseLDAPURL(ldapUrl)
		if err != nil {
			logger.Printf("Failed to parse ldapurl '%s'", ldapUrl)
			continue
		}
		vaild, err := authutil.CheckLDAPUserPassword(*u, bindDN, password, timeoutSecs, nil)
		if err != nil {
			//logger.Printf("Failed to parse %s", ldapUrl)
			continue
		}
		// the ldap exchange was successful (user might be invaid)
		return vaild, nil

	}
	if config.Base.HtpasswdFilename != "" {
		if *debug {
			logger.Printf("I have htpasswed filename")
		}
		buffer, err := ioutil.ReadFile(config.Base.HtpasswdFilename)
		if err != nil {
			return false, err
		}
		valid, err := authutil.CheckHtpasswdUserPassword(username, password, buffer)
		if err != nil {
			return false, err
		}
		return valid, nil
	}
	return false, nil
}

// returns application/json or text/html depending on the request. By default we assume the requester wants json
func getPreferredAcceptType(r *http.Request) string {
	preferredAcceptType := "application/json"
	acceptHeader, ok := r.Header["Accept"]
	if ok {
		for _, acceptValue := range acceptHeader {
			if strings.Contains(acceptValue, "text/html") {
				logger.Printf("Got it  %+v", acceptValue)
				preferredAcceptType = "text/html"
			}
		}
	}
	return preferredAcceptType
}

func (state *RuntimeState) writeHTMLLoginPage(w http.ResponseWriter, r *http.Request) error {
	displayData := loginPageTemplateData{Title: "Keymaster Login", ShowOauth2: state.Config.Oauth2.Enabled}
	t, err := template.New("webpage").Parse(loginFormText)
	if err != nil {
		logger.Printf("bad template %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return err
	}
	err = t.Execute(w, displayData)
	if err != nil {
		logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return err
	}
	return nil
}

func (state *RuntimeState) writeFailureResponse(w http.ResponseWriter, r *http.Request, code int, message string) {
	returnAcceptType := getPreferredAcceptType(r)
	if code == http.StatusUnauthorized && returnAcceptType != "text/html" {
		w.Header().Set("WWW-Authenticate", `Basic realm="User Credentials"`)
	}
	w.WriteHeader(code)
	publicErrorText := fmt.Sprintf("%d %s %s\n", code, http.StatusText(code), message)
	switch code {

	case http.StatusUnauthorized:
		switch returnAcceptType {
		case "text/html":
			// TODO: change by a message followed by an HTTP redirection
			state.writeHTMLLoginPage(w, r)
		default:
			w.Write([]byte(publicErrorText))
		}
	default:
		w.Write([]byte(publicErrorText))
	}
}

// returns true if the system is locked and sends message to the requester
func (state *RuntimeState) sendFailureToClientIfLocked(w http.ResponseWriter, r *http.Request) bool {
	var signerIsNull bool

	state.Mutex.Lock()
	signerIsNull = (state.Signer == nil)
	state.Mutex.Unlock()

	//all common security headers go here
	w.Header().Set("Strict-Transport-Security", "max-age=31536")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1")
	//w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' code.jquery.com; connect-src 'self'; img-src 'self'; style-src 'self';")
	w.Header().Set("Content-Security-Policy", "default-src 'self' code.jquery.com; style-src 'self' 'unsafe-inline';")

	if signerIsNull {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer has not been unlocked")
		return true
	}
	return false
}

// Inspired by http://stackoverflow.com/questions/21936332/idiomatic-way-of-requiring-http-basic-auth-in-go
func (state *RuntimeState) checkAuth(w http.ResponseWriter, r *http.Request) (string, int, error) {
	// We first check for cookies
	var authCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}
	if authCookie == nil {
		//For now try also http basic (to be deprecated)
		user, pass, ok := r.BasicAuth()
		if !ok {
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
			//toLoginOrBasicAuth(w, r)
			err := errors.New("check_Auth, Invalid or no auth header")
			return "", AuthTypeNone, err
		}
		state.Mutex.Lock()
		config := state.Config
		state.Mutex.Unlock()
		valid, err := checkUserPassword(user, pass, config)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return "", AuthTypeNone, err
		}
		if !valid {
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
			err := errors.New("Invalid Credentials")
			return "", AuthTypeNone, err
		}
		return user, AuthTypePassword, nil
	}

	//Critical section
	state.Mutex.Lock()
	info, ok := state.authCookie[authCookie.Value]
	state.Mutex.Unlock()

	if !ok {
		//redirect to login page?
		//better would be to return the content of the redirect form with a 401 code?
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		err := errors.New("Invalid Cookie")
		return "", AuthTypeNone, err
	}
	//check for expiration...
	if info.ExpiresAt.Before(time.Now()) {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		err := errors.New("Expired Cookie")
		return "", AuthTypeNone, err

	}
	return info.Username, info.AuthType, nil
}

const certgenPath = "/certgen/"

func (state *RuntimeState) certGenHandler(w http.ResponseWriter, r *http.Request) {
	var signerIsNull bool
	var keySigner crypto.Signer

	// copy runtime singer if not nil
	state.Mutex.Lock()
	signerIsNull = (state.Signer == nil)
	if !signerIsNull {
		keySigner = state.Signer
	}
	state.Mutex.Unlock()

	//local sanity tests
	if signerIsNull {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer not loaded")
		return
	}
	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, authLevel, err := state.checkAuth(w, r)
	if err != nil {
		logger.Printf("%v", err)

		return
	}

	sufficientAuthLevel := false
	// We should do an intersection operation here
	for _, certPref := range state.Config.Base.AllowedAuthBackendsForCerts {
		if certPref == proto.AuthTypePassword {
			sufficientAuthLevel = true
		}
	}
	// if you have u2f you can get the cert
	if (authLevel & AuthTypeU2F) == AuthTypeU2F {
		sufficientAuthLevel = true
	}

	if !sufficientAuthLevel {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Not enough auth level for getting certs")
		return
	}

	targetUser := r.URL.Path[len(certgenPath):]
	if authUser != targetUser {
		state.writeFailureResponse(w, r, http.StatusForbidden, "")
		logger.Printf("User %s asking for creds for %s", authUser, targetUser)
		return
	}
	if *debug {
		logger.Printf("auth succedded for %s", authUser)
	}

	switch r.Method {
	case "GET":
		if *debug {
			logger.Printf("Got client GET connection")
		}
		err = r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	case "POST":
		if *debug {
			logger.Printf("Got client POST connection")
		}
		err = r.ParseMultipartForm(1e7)
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}

	certType := "ssh"
	if val, ok := r.Form["type"]; ok {
		certType = val[0]
	}
	logger.Printf("cert type =%s", certType)

	switch certType {
	case "ssh":
		state.postAuthSSHCertHandler(w, r, targetUser, keySigner)
		return
	case "x509":
		state.postAuthX509CertHandler(w, r, targetUser, keySigner)
		return
	default:
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Unrecognized cert type")
		return
	}
	//SHOULD have never reached this!
	state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
	logger.Printf("Escape from default paths")
	return

}

func (state *RuntimeState) postAuthSSHCertHandler(w http.ResponseWriter, r *http.Request, targetUser string, keySigner crypto.Signer) {
	signer, err := ssh.NewSignerFromSigner(keySigner)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer failed to load")
		return
	}

	var cert string
	switch r.Method {
	case "GET":
		cert, err = certgen.GenSSHCertFileStringFromSSSDPublicKey(targetUser, signer, state.HostIdentity)
		if err != nil {
			http.NotFound(w, r)
			return
		}
	case "POST":
		file, _, err := r.FormFile("pubkeyfile")
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Missing public key file")
			return
		}
		defer file.Close()
		buf := new(bytes.Buffer)
		buf.ReadFrom(file)
		userPubKey := buf.String()
		//validKey, err := regexp.MatchString("^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) [a-zA-Z0-9/+]+=?=? .*$", userPubKey)
		validKey, err := regexp.MatchString("^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) [a-zA-Z0-9/+]+=?=? ?.{0,512}\n?$", userPubKey)
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
		if !validKey {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid File, bad re")
			logger.Printf("invalid file, bad re")
			return

		}

		cert, err = certgen.GenSSHCertFileString(targetUser, userPubKey, signer, state.HostIdentity)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			logger.Printf("signUserPubkey Err")
			return
		}

	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return

	}
	w.Header().Set("Content-Disposition", `attachment; filename="id_rsa-cert.pub"`)
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", cert)
	logger.Printf("Generated SSH Certifcate for %s", targetUser)
	go func(username string, certType string) {
		metricsMutex.Lock()
		defer metricsMutex.Unlock()
		certGenCounter.WithLabelValues(username, certType).Inc()
	}(targetUser, "ssh")
}

func (state *RuntimeState) postAuthX509CertHandler(w http.ResponseWriter, r *http.Request, targetUser string, keySigner crypto.Signer) {
	var cert string
	switch r.Method {
	case "POST":
		file, _, err := r.FormFile("pubkeyfile")
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Missing public key file")
			return
		}
		defer file.Close()
		buf := new(bytes.Buffer)
		buf.ReadFrom(file)

		block, _ := pem.Decode(buf.Bytes())
		if block == nil || block.Type != "PUBLIC KEY" {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid File, Unable to decode pem")
			logger.Printf("invalid file, unable to decode pem")
			return
		}
		userPub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Cannot parse public key")
			logger.Printf("Cannot parse public key")
			return
		}
		//tate.caCertDer
		caCert, err := x509.ParseCertificate(state.caCertDer)
		if err != nil {
			//state.writeFailureResponse(w, http.StatusBadRequest, "Cannot parse public key")
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			logger.Printf("Cannot parse CA Der data")
			return
		}
		derCert, err := certgen.GenUserX509Cert(targetUser, userPub, caCert, keySigner, state.KerberosRealm)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			logger.Printf("Cannot Generate x509cert")
			return
		}
		cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert}))

	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return

	}
	w.Header().Set("Content-Disposition", `attachment; filename="userCert.pem"`)
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", cert)
	logger.Printf("Generated x509 Certifcate for %s", targetUser)
	go func(username string, certType string) {
		metricsMutex.Lock()
		defer metricsMutex.Unlock()
		certGenCounter.WithLabelValues(username, certType).Inc()
	}(targetUser, "x509")
}

const secretInjectorPath = "/admin/inject"

func (state *RuntimeState) secretInjectorHandler(w http.ResponseWriter, r *http.Request) {
	// checks this is only allowed when using TLS client certs.. all other authn
	// mechanisms are considered invalid... for now no authz mechanisms are in place ie
	// Any user with a valid cert can use this handler
	if r.TLS == nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("We require TLS\n")
		return
	}

	if len(r.TLS.VerifiedChains) < 1 {
		state.writeFailureResponse(w, r, http.StatusForbidden, "")
		logger.Printf("Forbidden\n")
		return
	}
	clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
	logger.Printf("Got connection from %s", clientName)
	r.ParseForm()
	sshCAPassword, ok := r.Form["ssh_ca_password"]
	if !ok {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Post, missing data")
		logger.Printf("missing ssh_ca_password")
		return
	}
	state.Mutex.Lock()
	defer state.Mutex.Unlock()

	// TODO.. make network error blocks to goroutines
	if state.Signer != nil {
		state.writeFailureResponse(w, r, http.StatusConflict, "Conflict post, signer already unlocked")
		logger.Printf("Signer not null, already unlocked")
		return
	}

	decbuf := bytes.NewBuffer(state.SSHCARawFileContent)

	armorBlock, err := armor.Decode(decbuf)
	if err != nil {
		logger.Printf("Cannot decode armored file")
		return
	}
	password := []byte(sshCAPassword[0])
	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		// If the given passphrase isn't correct, the function will be called again, forever.
		// This method will fail fast.
		// Ref: https://godoc.org/golang.org/x/crypto/openpgp#PromptFunction
		if failed {
			return nil, errors.New("decryption failed")
		}
		failed = true
		return password, nil
	}
	md, err := openpgp.ReadMessage(armorBlock.Body, nil, prompt, nil)
	if err != nil {
		logger.Printf("cannot read message")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Unlocking key")
		return
	}

	plaintextBytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return
	}

	signer, err := getSignerFromPEMBytes(plaintextBytes)
	if err != nil {
		logger.Printf("Cannot parse Priave Key file")
		return
	}

	logger.Printf("About to generate cader %s", clientName)
	state.caCertDer, err = generateCADer(state, signer)
	if err != nil {
		logger.Printf("Cannot generate CA Der")
		return
	}
	sendMessage := false
	if state.Signer == nil {
		sendMessage = true
	}

	// Assignmet of signer MUST be the last operation after
	// all error checks
	state.Signer = signer
	if sendMessage {
		state.SignerIsReady <- true
	}

	// TODO... make success a goroutine
	w.WriteHeader(200)
	fmt.Fprintf(w, "OK\n")
	//fmt.Fprintf(w, "%+v\n", r.TLS)
}

const publicPath = "/public/"

const loginFormPath = "/public/loginForm"

func (state *RuntimeState) publicPathHandler(w http.ResponseWriter, r *http.Request) {
	var signerIsNull bool

	// check if initialized(singer  not nil)
	state.Mutex.Lock()
	signerIsNull = (state.Signer == nil)
	state.Mutex.Unlock()
	if signerIsNull {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer not loaded")
		return
	}

	target := r.URL.Path[len(publicPath):]

	switch target {
	case "loginForm":
		w.WriteHeader(200)
		//fmt.Fprintf(w, "%s", loginFormText)
		state.writeHTMLLoginPage(w, r)
		return
	case "x509ca":
		pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: state.caCertDer}))

		w.Header().Set("Content-Disposition", `attachment; filename="id_rsa-cert.pub"`)
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", pemCert)
	default:
		state.writeFailureResponse(w, r, http.StatusNotFound, "")
		return
		//w.WriteHeader(200)
		//fmt.Fprintf(w, "OK\n")
	}
}

const authCookieName = "auth_cookie"
const randomStringEntropyBytes = 32
const maxAgeSecondsAuthCookie = 300

func genRandomString() (string, error) {
	size := randomStringEntropyBytes
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(rb), nil
}

//const loginPath = "/api/v0/login"

func (state *RuntimeState) loginHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	//Check for valid method here?
	switch r.Method {
	case "GET":
		if *debug {
			logger.Printf("Got client GET connection")
		}
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	case "POST":
		if *debug {
			logger.Printf("Got client POST connection")
		}
		//err := r.ParseMultipartForm(1e7)
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
		//logger.Printf("req =%+v", r)
	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}

	//First headers and then check form
	username, password, ok := r.BasicAuth()
	if !ok {
		//var username string
		if val, ok := r.Form["username"]; ok {
			if len(val) > 1 {
				state.writeFailureResponse(w, r, http.StatusBadRequest, "Just one username allowed")
				logger.Printf("Login with multiple usernames")
				return
			}
			username = val[0]
		}
		//var password string
		if val, ok := r.Form["password"]; ok {
			if len(val) > 1 {
				state.writeFailureResponse(w, r, http.StatusBadRequest, "Just one password allowed")
				logger.Printf("Login with passwords")
				return
			}
			password = val[0]
		}

		if len(username) < 1 || len(password) < 1 {
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
			return
		}
	}

	valid, err := checkUserPassword(username, password, state.Config)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if !valid {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		logger.Printf("Invalid login for %s", username)
		//err := errors.New("Invalid Credentials")
		return
	}
	//
	cookieVal, err := genRandomString()
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "error internal")
		logger.Println(err)
		return
	}

	expiration := time.Now().Add(time.Duration(maxAgeSecondsAuthCookie) * time.Second)
	savedUserInfo := authInfo{Username: username, ExpiresAt: expiration, AuthType: AuthTypePassword}
	state.Mutex.Lock()
	state.authCookie[cookieVal] = savedUserInfo
	state.Mutex.Unlock()

	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal, Expires: expiration, Path: "/", HttpOnly: true, Secure: true}

	//use handler with original request.
	http.SetCookie(w, &authCookie)

	//return user, nil

	//logger.Printf("cert type =%s", certType)
	returnAcceptType := "application/json"
	acceptHeader, ok := r.Header["Accept"]
	if ok {
		for _, acceptValue := range acceptHeader {
			if strings.Contains(acceptValue, "text/html") {
				logger.Printf("Got it  %+v", acceptValue)
				returnAcceptType = "text/html"
			}
		}
	}

	// Compute the cert prefs
	var certBackends []string
	for _, certPref := range state.Config.Base.AllowedAuthBackendsForCerts {
		if certPref == proto.AuthTypePassword {
			certBackends = append(certBackends, proto.AuthTypePassword)
		}
		if certPref == proto.AuthTypeU2F {
			certBackends = append(certBackends, proto.AuthTypeU2F)
		}
	}
	if len(certBackends) == 0 {
		certBackends = append(certBackends, proto.AuthTypeU2F)
	}

	// TODO: The cert backend should depend also on per user preferences.
	loginResponse := proto.LoginResponse{Message: "success",
		CertAuthBackend: certBackends}
	switch returnAcceptType {
	case "text/html":
		http.Redirect(w, r, profilePath, 302)
	default:
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(loginResponse)
		//fmt.Fprintf(w, "Success!")
	}
	return

}

///
const logoutPath = "/api/v0/logout"

func (state *RuntimeState) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// We first check for cookies
	var authCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}

	if authCookie != nil {
		//Critical section
		state.Mutex.Lock()
		_, ok := state.authCookie[authCookie.Value]
		if ok {
			delete(state.authCookie, authCookie.Value)
		}
		state.Mutex.Unlock()
	}
	//redirect to login
	http.Redirect(w, r, profilePath, 302)
}

////////////////////////////

func getRegistrationArray(U2fAuthData map[int64]*u2fAuthData) (regArray []u2f.Registration) {
	for _, data := range U2fAuthData {
		if data.Enabled {
			regArray = append(regArray, *data.Registration)
		}
	}
	return regArray
}

const u2fRegustisterRequestPath = "/u2f/RegisterRequest"

func (state *RuntimeState) u2fRegisterRequest(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, _, err := state.checkAuth(w, r)
	if err != nil {
		logger.Printf("%v", err)

		return
	}

	profile, _, err := state.LoadUserProfile(authUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}

	c, err := u2f.NewChallenge(u2fAppID, u2fTrustedFacets)
	if err != nil {
		logger.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	profile.RegistrationChallenge = c
	registrations := getRegistrationArray(profile.U2fAuthData)
	req := u2f.NewWebRegisterRequest(c, registrations)

	logger.Printf("registerRequest: %+v", req)
	err = state.SaveUserProfile(authUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(req)
}

const u2fRegisterRequesponsePath = "/u2f/RegisterResponse"

func (state *RuntimeState) u2fRegisterResponse(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, _, err := state.checkAuth(w, r)
	if err != nil {
		logger.Printf("%v", err)

		return
	}

	var regResp u2f.RegisterResponse
	if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	profile, _, err := state.LoadUserProfile(authUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	if profile.RegistrationChallenge == nil {
		http.Error(w, "challenge not found", http.StatusBadRequest)
		return
	}

	// TODO: use yubikey or get the feitan cert :(
	u2fConfig := u2f.Config{SkipAttestationVerify: true}

	reg, err := u2f.Register(regResp, *profile.RegistrationChallenge, &u2fConfig)
	if err != nil {
		logger.Printf("u2f.Register error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}

	newReg := u2fAuthData{Counter: 0,
		Registration: reg,
		Enabled:      true,
		CreatedAt:    time.Now(),
		CreatorAddr:  r.RemoteAddr,
	}
	newIndex := newReg.CreatedAt.Unix()
	profile.U2fAuthData[newIndex] = &newReg
	//registrations = append(registrations, *reg)
	//counter = 0

	logger.Printf("Registration success: %+v", reg)

	profile.RegistrationChallenge = nil
	err = state.SaveUserProfile(authUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("success"))
}

const u2fSignRequestPath = "/u2f/SignRequest"

func (state *RuntimeState) u2fSignRequest(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, _, err := state.checkAuth(w, r)
	if err != nil {
		logger.Printf("%v", err)

		return
	}

	//////////
	profile, ok, err := state.LoadUserProfile(authUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	/////////
	if !ok {
		http.Error(w, "No regstered data", http.StatusBadRequest)
		return
	}
	registrations := getRegistrationArray(profile.U2fAuthData)
	if len(registrations) < 1 {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	c, err := u2f.NewChallenge(u2fAppID, u2fTrustedFacets)
	if err != nil {
		logger.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	profile.U2fAuthChallenge = c
	req := c.SignRequest(registrations)
	if *debug {
		logger.Printf("Sign request: %+v", req)
	}

	err = state.SaveUserProfile(authUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(req); err != nil {
		logger.Printf("json encofing error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

const u2fSignResponsePath = "/u2f/SignResponse"

func (state *RuntimeState) u2fSignResponse(w http.ResponseWriter, r *http.Request) {
	// User must be logged in
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, _, err := state.checkAuth(w, r)
	if err != nil {
		logger.Printf("%v", err)
		return
	}

	// If successful I need to update the cookie
	var authCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}

	//now the actual work
	var signResp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&signResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	logger.Printf("signResponse: %+v", signResp)

	profile, ok, err := state.LoadUserProfile(authUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}

	/////////
	if !ok {
		http.Error(w, "No regstered data", http.StatusBadRequest)
		return
	}
	registrations := getRegistrationArray(profile.U2fAuthData)
	if len(registrations) < 1 {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	if profile.U2fAuthChallenge == nil {
		http.Error(w, "challenge missing", http.StatusBadRequest)
		return
	}
	if registrations == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	//var err error
	for i, u2fReg := range profile.U2fAuthData {
		newCounter, authErr := u2fReg.Registration.Authenticate(signResp, *profile.U2fAuthChallenge, u2fReg.Counter)
		if authErr == nil {
			logger.Printf("newCounter: %d", newCounter)
			//counter = newCounter
			u2fReg.Counter = newCounter
			//profile.U2fAuthData[i].Counter = newCounter
			u2fReg.Counter = newCounter
			profile.U2fAuthData[i] = u2fReg
			profile.U2fAuthChallenge = nil

			// update cookie if found, this should be also a critical section
			if authCookie != nil {
				state.Mutex.Lock()
				info, ok := state.authCookie[authCookie.Value]
				if ok {
					info.AuthType = AuthTypeU2F
					state.authCookie[authCookie.Value] = info
				}
				state.Mutex.Unlock()
			}

			err = state.SaveUserProfile(authUser, profile)
			if err != nil {
				logger.Printf("Saving profile error: %v", err)
				http.Error(w, "error", http.StatusInternalServerError)
				return
			}

			// TODO: update local cookie state
			w.Write([]byte("success"))
			return
		}
	}

	logger.Printf("VerifySignResponse error: %v", err)
	http.Error(w, "error verifying response", http.StatusInternalServerError)
}

const profilePath = "/profile/"

func (state *RuntimeState) profileHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, _, err := state.checkAuth(w, r)
	if err != nil {
		logger.Printf("%v", err)

		return
	}
	//find the user token
	profile, _, err := state.LoadUserProfile(authUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	displayData := profilePageTemplateData{Username: authUser,
		Title:     "Keymaster User Profile",
		JSSources: []string{"//code.jquery.com/jquery-1.12.4.min.js", "/static/u2f-api.js", "/static/keymaster-u2f.js"}}
	for i, tokenInfo := range profile.U2fAuthData {

		deviceData := registeredU2FTokenDisplayInfo{
			DeviceData: fmt.Sprintf("%+v", tokenInfo.Registration.AttestationCert.Subject.CommonName),
			Enabled:    tokenInfo.Enabled,
			Name:       tokenInfo.Name,
			Index:      i}
		displayData.RegisteredToken = append(displayData.RegisteredToken, deviceData)
	}

	logger.Printf("%v", displayData)

	t, err := template.New("webpage").Parse(profileHTML)
	if err != nil {
		logger.Printf("bad template %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	err = t.Execute(w, displayData)
	if err != nil {
		logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	//w.Write([]byte(indexHTML))
}

const u2fTokenManagementPath = "/api/v0/manageU2FToken"

// TODO: add duplicate action filter via cookies (for browser context).

func (state *RuntimeState) u2fTokenManagerHandler(w http.ResponseWriter, r *http.Request) {
	// User must be logged in
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, _, err := state.checkAuth(w, r)
	if err != nil {
		logger.Printf("%v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	// TODO: ensure is a valid method (POST)
	err = r.ParseForm()
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
		return
	}
	if *debug {
		logger.Printf("Form: %+v", r.Form)
	}

	// Check params
	if r.Form.Get("username") != authUser {
		logger.Printf("bad username authUser=%s requested=%s", authUser, r.Form.Get("username"))
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return
	}

	tokenIndex, err := strconv.ParseInt(r.Form.Get("index"), 10, 64)
	if err != nil {
		logger.Printf("tokenindex is not a number")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "tokenindex is not a number")
		return
	}

	//Do a redirect
	profile, _, err := state.LoadUserProfile(authUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}

	// Todo: check for negative values
	_, ok := profile.U2fAuthData[tokenIndex]
	if !ok {
		//if tokenIndex >= len(profile.U2fAuthData) {
		logger.Printf("bad index number")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "bad index Value")
		return

	}

	actionName := r.Form.Get("action")
	switch actionName {
	case "Update":
		tokenName := r.Form.Get("name")
		if m, _ := regexp.MatchString("^[a-zA-Z0-9_ ]+$", tokenName); !m {
			logger.Printf("%s", tokenName)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "invalidtokenName")
			return
		}
		profile.U2fAuthData[tokenIndex].Name = tokenName
	case "Disable":
		profile.U2fAuthData[tokenIndex].Enabled = false
	case "Enable":
		profile.U2fAuthData[tokenIndex].Enabled = true
	case "Delete":
		delete(profile.U2fAuthData, tokenIndex)
	default:
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Operation")
		return
	}

	err = state.SaveUserProfile(authUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	// Success!
	returnAcceptType := getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		http.Redirect(w, r, profilePath, 302)
	default:
		w.WriteHeader(200)
		fmt.Fprintf(w, "Success!")
	}
	return
}

const clientConfHandlerPath = "/public/clientConfig"
const clientConfigText = `base:
    gen_cert_urls: "%s"
`

func (state *RuntimeState) serveClientConfHandler(w http.ResponseWriter, r *http.Request) {
	//w.WriteHeader(200)
	w.Header().Set("Content-Type", "text/yaml")
	fmt.Fprintf(w, clientConfigText, u2fAppID)
}

func (state *RuntimeState) defaultPathHandler(w http.ResponseWriter, r *http.Request) {
	//redirect to profile
	if r.URL.Path[:] == "/" {
		http.Redirect(w, r, profilePath, 302)
		return
	}
	http.Error(w, "error not found", http.StatusNotFound)
}

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
}

func init() {
	prometheus.MustRegister(certGenCounter)
}

func main() {
	flag.Usage = Usage
	flag.Parse()

	tricorder.RegisterFlags()
	circularBuffer := logbuf.New()
	if circularBuffer == nil {
		panic("Cannot create circular buffer")
	}
	logger = stdlog.New(circularBuffer, "", stdlog.LstdFlags)

	if *generateConfig {
		err := generateNewConfig(*configFilename)
		if err != nil {
			panic(err)
		}
		return
	}

	runtimeState, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		panic(err)
	}
	if *debug || true {
		logger.Printf("After load verify")
	}

	adminDashboard := newAdminDashboard(circularBuffer)
	// Expose the registered metrics via HTTP.
	http.Handle("/", adminDashboard)
	http.Handle("/prometheus_metrics", prometheus.Handler())
	http.HandleFunc(secretInjectorPath, runtimeState.secretInjectorHandler)

	serviceMux := http.NewServeMux()
	serviceMux.HandleFunc(certgenPath, runtimeState.certGenHandler)
	serviceMux.HandleFunc(publicPath, runtimeState.publicPathHandler)
	serviceMux.HandleFunc(proto.LoginPath, runtimeState.loginHandler)
	serviceMux.HandleFunc(logoutPath, runtimeState.logoutHandler)
	serviceMux.HandleFunc(profilePath, runtimeState.profileHandler)

	staticFilesPath := filepath.Join(runtimeState.Config.Base.SharedDataDirectory, "static_files")
	serviceMux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticFilesPath))))
	serviceMux.HandleFunc(u2fRegustisterRequestPath, runtimeState.u2fRegisterRequest)
	serviceMux.HandleFunc(u2fRegisterRequesponsePath, runtimeState.u2fRegisterResponse)
	serviceMux.HandleFunc(u2fSignRequestPath, runtimeState.u2fSignRequest)
	serviceMux.HandleFunc(u2fSignResponsePath, runtimeState.u2fSignResponse)
	serviceMux.HandleFunc(u2fTokenManagementPath, runtimeState.u2fTokenManagerHandler)
	serviceMux.HandleFunc(oauth2LoginBeginPath, runtimeState.oauth2DoRedirectoToProviderHandler)
	serviceMux.HandleFunc(redirectPath, runtimeState.oauth2RedirectPathHandler)
	serviceMux.HandleFunc(clientConfHandlerPath, runtimeState.serveClientConfHandler)
	serviceMux.HandleFunc("/", runtimeState.defaultPathHandler)

	cfg := &tls.Config{
		ClientCAs:                runtimeState.ClientCAPool,
		ClientAuth:               tls.VerifyClientCertIfGiven,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	adminSrv := &http.Server{
		Addr:         runtimeState.Config.Base.AdminAddress,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	go func(msg string) {
		err := adminSrv.ListenAndServeTLS(
			runtimeState.Config.Base.TLSCertFilename,
			runtimeState.Config.Base.TLSKeyFilename)
		if err != nil {
			panic(err)
		}

	}("done")

	isReady := <-runtimeState.SignerIsReady
	if isReady != true {
		panic("got bad singer ready data")
	}

	serviceSrv := &http.Server{
		Addr:         runtimeState.Config.Base.HttpAddress,
		Handler:      serviceMux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	err = serviceSrv.ListenAndServeTLS(
		runtimeState.Config.Base.TLSCertFilename,
		runtimeState.Config.Base.TLSKeyFilename)
	if err != nil {
		panic(err)
	}
	healthserver.SetReady()
}
