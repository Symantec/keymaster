package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/Dominator/lib/log/serverlogger"
	"github.com/Symantec/Dominator/lib/srpc"
	"github.com/Symantec/keymaster/keymasterd/eventnotifier"
	"github.com/Symantec/keymaster/lib/authutil"
	"github.com/Symantec/keymaster/lib/certgen"
	"github.com/Symantec/keymaster/lib/pwauth"
	"github.com/Symantec/keymaster/lib/webapi/v0/proto"
	"github.com/Symantec/keymaster/proto/eventmon"
	"github.com/Symantec/tricorder/go/healthserver"
	"github.com/Symantec/tricorder/go/tricorder"
	"github.com/Symantec/tricorder/go/tricorder/units"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tstranex/u2f"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

const (
	AuthTypeNone     = 0
	AuthTypePassword = 1 << iota
	AuthTypeFederated
	AuthTypeU2F
	AuthTypeSymantecVIP
)

const AuthTypeAny = 0xFFFF

type authInfo struct {
	ExpiresAt time.Time
	Username  string
	AuthType  int
}

type authInfoJWT struct {
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	Expiration int64    `json:"exp,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	TokenType  string   `json:"token_type"`
	AuthType   int      `json:"auth_type"`
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
	//U2fAuthChallenge      *u2f.Challenge
}

type localUserData struct {
	U2fAuthChallenge *u2f.Challenge
	ExpiresAt        time.Time
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
	//authCookie          map[string]authInfo
	localAuthData map[string]localUserData
	SignerIsReady chan bool
	Mutex         sync.Mutex
	//userProfile         map[string]userProfile
	pendingOauth2        map[string]pendingAuth2Request
	storageRWMutex       sync.RWMutex
	db                   *sql.DB
	dbType               string
	cacheDB              *sql.DB
	remoteDBQueryTimeout time.Duration
	htmlTemplate         *template.Template
	passwordChecker      pwauth.PasswordAuthenticator
	KeymasterPublicKeys  []crypto.PublicKey
}

const redirectPath = "/auth/oauth2/callback"
const secsBetweenCleanup = 30

var (
	Version          = "No version provided"
	configFilename   = flag.String("config", "config.yml", "The filename of the configuration")
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
	authOperationCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "keymaster_auth_operation_counter",
			Help: "Keymaster_auth_operation_counter",
		},
		[]string{"client_type", "type", "result"},
	)

	externalServiceDurationTotal = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "keymaster_external_service_request_duration",
			Help:    "Total amount of time spent non-errored external checks in ms",
			Buckets: []float64{5, 7.5, 10, 15, 25, 50, 75, 100, 150, 250, 500, 750, 1000, 1500, 2500, 5000},
		},
		[]string{"service_name"},
	)
	tricorderLDAPExternalServiceDurationTotal    = tricorder.NewGeometricBucketer(5, 5000.0).NewCumulativeDistribution()
	tricorderStorageExternalServiceDurationTotal = tricorder.NewGeometricBucketer(1, 2000.0).NewCumulativeDistribution()
	tricorderVIPExternalServiceDurationTotal     = tricorder.NewGeometricBucketer(5, 5000.0).NewCumulativeDistribution()

	certDurationHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "keymaster_cert_duration",
			Help:    "Duration of certs in seconds",
			Buckets: []float64{15, 30, 60, 120, 300, 600, 3600, 7200, 36000, 57600, 72000, 86400, 172800},
		},
		[]string{"cert_type", "stage"},
	)

	logger log.DebugLogger
	// TODO(rgooch): Pass this in rather than use a global variable.
	eventNotifier *eventnotifier.EventNotifier
)

func metricLogAuthOperation(clientType string, authType string, success bool) {
	validStr := strconv.FormatBool(success)
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	authOperationCounter.WithLabelValues(clientType, authType, validStr).Inc()
}

func metricLogExternalServiceDuration(service string, duration time.Duration) {
	val := duration.Seconds() * 1000
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	externalServiceDurationTotal.WithLabelValues(service).Observe(val)
	switch service {
	case "ldap":
		tricorderLDAPExternalServiceDurationTotal.Add(duration)
	case "vip":
		tricorderVIPExternalServiceDurationTotal.Add(duration)
	case "storage-read":
		tricorderStorageExternalServiceDurationTotal.Add(duration)
	case "storage-save":
		tricorderStorageExternalServiceDurationTotal.Add(duration)
	}
}

func metricLogCertDuration(certType string, stage string, val float64) {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	certDurationHistogram.WithLabelValues(certType, stage).Observe(val)
}

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
		//
		initPendingSize := len(state.pendingOauth2)
		for key, oauth2Pending := range state.pendingOauth2 {
			if oauth2Pending.ExpiresAt.Before(time.Now()) {
				delete(state.pendingOauth2, key)
			}
		}
		finalPendingSize := len(state.pendingOauth2)

		//localAuthData
		initPendingLocal := len(state.localAuthData)
		for key, localAuth := range state.localAuthData {
			if localAuth.ExpiresAt.Before(time.Now()) {
				delete(state.localAuthData, key)
			}
		}
		finalPendingLocal := len(state.localAuthData)

		state.Mutex.Unlock()
		logger.Debugf(3, "Pending Cookie sizes: before(%d) after(%d)",
			initPendingSize, finalPendingSize)
		logger.Debugf(3, "Pending Cookie sizes: before(%d) after(%d)",
			initPendingLocal, finalPendingLocal)
		time.Sleep(time.Duration(secsBetweenCleanup) * time.Second)
	}

}

func convertToBindDN(username string, bind_pattern string) string {
	return fmt.Sprintf(bind_pattern, username)
}

func checkUserPassword(username string, password string, config AppConfigFile, passwordChecker pwauth.PasswordAuthenticator, r *http.Request) (bool, error) {
	clientType := getClientType(r)
	if passwordChecker != nil {
		logger.Debugf(3, "checking auth with passwordChecker")
		isLDAP := false
		if len(config.Ldap.LDAP_Target_URLs) > 0 {
			isLDAP = true
		}

		start := time.Now()
		valid, err := passwordChecker.PasswordAuthenticate(username, []byte(password))
		if err != nil {
			return false, err
		}
		if isLDAP {
			metricLogExternalServiceDuration("ldap", time.Since(start))
		}
		logger.Debugf(3, "pwdChaker output = %d", valid)
		metricLogAuthOperation(clientType, "password", valid)
		return valid, nil
	}

	if config.Base.HtpasswdFilename != "" {
		logger.Debugf(3, "I have htpasswed filename")
		buffer, err := ioutil.ReadFile(config.Base.HtpasswdFilename)
		if err != nil {
			return false, err
		}
		valid, err := authutil.CheckHtpasswdUserPassword(username, password, buffer)
		if err != nil {
			return false, err
		}
		metricLogAuthOperation(clientType, "password", valid)
		return valid, nil
	}
	metricLogAuthOperation(clientType, "password", false)
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

func browserSupportsU2F(r *http.Request) bool {
	if strings.Contains(r.UserAgent(), "Chrome/") {
		return true
	}
	if strings.Contains(r.UserAgent(), "Presto/") {
		return true
	}
	//Once FF support reaches main we can remove these silly checks
	if strings.Contains(r.UserAgent(), "Firefox/57") ||
		strings.Contains(r.UserAgent(), "Firefox/58") ||
		strings.Contains(r.UserAgent(), "Firefox/59") ||
		strings.Contains(r.UserAgent(), "Firefox/6") {
		return true
	}
	return false
}

func getClientType(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	preferredAcceptType := getPreferredAcceptType(r)
	switch preferredAcceptType {
	case "text/html":
		return "browser"
	case "application/json":
		if len(r.Referer()) > 1 {
			return "browser"
		}
		return "cli"
	default:
		return "unknown"
	}
}

func (state *RuntimeState) writeHTML2FAAuthPage(w http.ResponseWriter, r *http.Request,
	loginDestination string) error {
	JSSources := []string{"/static/jquery-1.12.4.patched.min.js", "/static/u2f-api.js"}
	showU2F := browserSupportsU2F(r)
	if showU2F {
		JSSources = []string{"/static/jquery-1.12.4.patched.min.js", "/static/u2f-api.js", "/static/webui-2fa-u2f.js"}
	}
	displayData := secondFactorAuthTemplateData{
		Title:            "Keymaster 2FA Auth",
		JSSources:        JSSources,
		ShowOTP:          state.Config.SymantecVIP.Enabled,
		ShowU2F:          showU2F,
		LoginDestination: loginDestination}
	err := state.htmlTemplate.ExecuteTemplate(w, "secondFactorLoginPage", displayData)
	if err != nil {
		logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return err
	}
	return nil
}

func (state *RuntimeState) writeHTMLLoginPage(w http.ResponseWriter, r *http.Request,
	loginDestination string) error {
	//footerText := state.getFooterText()
	displayData := loginPageTemplateData{
		Title:            "Keymaster Login",
		ShowOauth2:       state.Config.Oauth2.Enabled,
		HideStdLogin:     state.Config.Base.HideStandardLogin,
		LoginDestination: loginDestination}
	err := state.htmlTemplate.ExecuteTemplate(w, "loginPage", displayData)
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
			var authCookie *http.Cookie
			for _, cookie := range r.Cookies() {
				if cookie.Name != authCookieName {
					continue
				}
				authCookie = cookie
			}
			loginDestnation := profilePath
			if r.URL.Path == idpOpenIDCAuthorizationPath {
				loginDestnation = r.URL.String()
			}
			if r.Method == "POST" {
				/// assume it has been parsed... otherwise why are we here?
				if r.Form.Get("login_destination") != "" {
					loginDestnation = r.Form.Get("login_destination")
				}
			}
			if authCookie == nil {
				// TODO: change by a message followed by an HTTP redirection
				state.writeHTMLLoginPage(w, r, loginDestnation)
				return
			}
			info, err := state.getAuthInfoFromAuthJWT(authCookie.Value)
			if err != nil {
				logger.Debugf(3, "write failure state, error from getinfo authInfoJWT")
				state.writeHTMLLoginPage(w, r, loginDestnation)
				return
			}
			if info.ExpiresAt.Before(time.Now()) {
				state.writeHTMLLoginPage(w, r, loginDestnation)
				return
			}
			if (info.AuthType & AuthTypePassword) == AuthTypePassword {
				state.writeHTML2FAAuthPage(w, r, loginDestnation)
				return
			}
			state.writeHTMLLoginPage(w, r, loginDestnation)
			return

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
	w.Header().Set("Content-Security-Policy", "default-src 'self' ;style-src 'self' fonts.googleapis.com 'unsafe-inline'; font-src fonts.gstatic.com fonts.googleapis.com")

	if signerIsNull {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer has not been unlocked")
		return true
	}
	return false
}

func (state *RuntimeState) setNewAuthCookie(w http.ResponseWriter, username string, authlevel int) (string, error) {
	cookieVal, err := state.genNewSerializedAuthJWT(username, authlevel)
	if err != nil {
		logger.Println(err)
		return "", err
	}
	expiration := time.Now().Add(time.Duration(maxAgeSecondsAuthCookie) * time.Second)
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal, Expires: expiration, Path: "/", HttpOnly: true, Secure: true}

	//use handler with original request.
	if w != nil {
		http.SetCookie(w, &authCookie)
	}
	return cookieVal, nil
}

func (state *RuntimeState) updateAuthCookieAuthlevel(w http.ResponseWriter, r *http.Request, authlevel int) (string, error) {
	var authCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}
	if authCookie == nil {
		err := errors.New("cannot find authCookie")
		return "", err
	}

	var err error
	cookieVal, err := state.updateAuthJWTWithNewAuthLevel(authCookie.Value, authlevel)
	if err != nil {
		return "", err
	}

	updatedAuthCookie := http.Cookie{Name: authCookieName, Value: cookieVal, Expires: authCookie.Expires, Path: "/", HttpOnly: true, Secure: true}
	logger.Debugf(3, "about to update authCookie")
	http.SetCookie(w, &updatedAuthCookie)
	return authCookie.Value, nil
}

// Inspired by http://stackoverflow.com/questions/21936332/idiomatic-way-of-requiring-http-basic-auth-in-go
func (state *RuntimeState) checkAuth(w http.ResponseWriter, r *http.Request, requiredAuthType int) (string, int, error) {
	// Check csrf
	if r.Method != "GET" {
		referer := r.Referer()
		if len(referer) > 0 && len(r.Host) > 0 {
			logger.Debugf(3, "ref =%s, host=%s", referer, r.Host)
			refererURL, err := url.Parse(referer)
			if err != nil {
				return "", AuthTypeNone, err
			}
			logger.Debugf(3, "refHost =%s, host=%s", refererURL.Host, r.Host)
			if refererURL.Host != r.Host {
				logger.Printf("CSRF detected.... rejecting with a 400")
				state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
				err := errors.New("CSRF detected... rejecting")
				return "", AuthTypeNone, err

			}
		}
	}

	// We first check for cookies
	var authCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}
	if authCookie == nil {

		if (AuthTypePassword & requiredAuthType) == 0 {
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
			err := errors.New("Insufficeint Auth Level passwd")
			return "", AuthTypeNone, err
		}

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
		valid, err := checkUserPassword(user, pass, config, state.passwordChecker, r)
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
	info, err := state.getAuthInfoFromAuthJWT(authCookie.Value)
	if err != nil {
		//TODO check between internal and bad cookie error
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
	if (info.AuthType & requiredAuthType) == 0 {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		err := errors.New("Insufficeint Auth Level")
		return "", info.AuthType, err
	}
	return info.Username, info.AuthType, nil
}

func (state *RuntimeState) getRequiredWebUIAuthLevel() int {
	AuthLevel := 0
	for _, webUIPref := range state.Config.Base.AllowedAuthBackendsForWebUI {
		if webUIPref == proto.AuthTypePassword {
			AuthLevel |= AuthTypePassword
		}
		if webUIPref == proto.AuthTypeFederated {
			AuthLevel |= AuthTypeFederated
		}
		if webUIPref == proto.AuthTypeU2F {
			AuthLevel |= AuthTypeU2F
		}

		if webUIPref == proto.AuthTypeSymantecVIP {
			AuthLevel |= AuthTypeSymantecVIP
		}
	}
	return AuthLevel
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
	authUser, authLevel, err := state.checkAuth(w, r, AuthTypeAny)
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
		if certPref == proto.AuthTypeU2F && ((authLevel & AuthTypeU2F) == AuthTypeU2F) {
			sufficientAuthLevel = true
		}
		if certPref == proto.AuthTypeSymantecVIP && ((authLevel & AuthTypeSymantecVIP) == AuthTypeSymantecVIP) {
			sufficientAuthLevel = true
		}
	}
	// if you have u2f you can always get the cert
	if (authLevel & AuthTypeU2F) == AuthTypeU2F {
		sufficientAuthLevel = true
	}

	if !sufficientAuthLevel {
		logger.Printf("Not enough auth level for getting certs")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Not enough auth level for getting certs")
		return
	}

	targetUser := r.URL.Path[len(certgenPath):]
	if authUser != targetUser {
		state.writeFailureResponse(w, r, http.StatusForbidden, "")
		logger.Printf("User %s asking for creds for %s", authUser, targetUser)
		return
	}
	logger.Debugf(3, "auth succedded for %s", authUser)

	switch r.Method {
	case "GET":
		logger.Debugf(3, "Got client GET connection")
		err = r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	case "POST":
		logger.Debugf(3, "Got client POST connection")
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

	duration := time.Duration(24 * time.Hour)
	if formDuration, ok := r.Form["duration"]; ok {
		stringDuration := formDuration[0]
		newDuration, err := time.ParseDuration(stringDuration)
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form (duration)")
			return
		}
		metricLogCertDuration("unparsed", "requested", float64(newDuration.Seconds()))
		if newDuration > duration {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form (invalid duration)")
			return
		}
		duration = newDuration
	}

	certType := "ssh"
	if val, ok := r.Form["type"]; ok {
		certType = val[0]
	}
	logger.Printf("cert type =%s", certType)

	switch certType {
	case "ssh":
		state.postAuthSSHCertHandler(w, r, targetUser, keySigner, duration)
		return
	case "x509":
		state.postAuthX509CertHandler(w, r, targetUser, keySigner, duration, false)
		return
	case "x509-kubernetes":
		state.postAuthX509CertHandler(w, r, targetUser, keySigner, duration, true)
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

func (state *RuntimeState) postAuthSSHCertHandler(
	w http.ResponseWriter, r *http.Request, targetUser string,
	keySigner crypto.Signer, duration time.Duration) {
	signer, err := ssh.NewSignerFromSigner(keySigner)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer failed to load")
		return
	}

	var cert string
	var certBytes []byte
	switch r.Method {
	case "GET":
		cert, certBytes, err = certgen.GenSSHCertFileStringFromSSSDPublicKey(targetUser, signer, state.HostIdentity, duration)
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

		cert, certBytes, err = certgen.GenSSHCertFileString(targetUser, userPubKey, signer, state.HostIdentity, duration)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			logger.Printf("signUserPubkey Err")
			return
		}

	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return

	}
	eventNotifier.PublishSSH(certBytes)
	metricLogCertDuration("ssh", "granted", float64(duration.Seconds()))

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

func (state *RuntimeState) getUserGroups(username string) ([]string, error) {
	ldapConfig := state.Config.UserInfo.Ldap
	var timeoutSecs uint
	timeoutSecs = 2
	//for _, ldapUrl := range ldapConfig.LDAPTargetURLs {
	for _, ldapUrl := range strings.Split(ldapConfig.LDAPTargetURLs, ",") {
		if len(ldapUrl) < 1 {
			continue
		}
		u, err := authutil.ParseLDAPURL(ldapUrl)
		if err != nil {
			logger.Printf("Failed to parse ldapurl '%s'", ldapUrl)
			continue
		}
		groups, err := authutil.GetLDAPUserGroups(*u,
			ldapConfig.BindUsername, ldapConfig.BindPassword,
			timeoutSecs, nil, username,
			ldapConfig.UserSearchBaseDNs, ldapConfig.UserSearchFilter)
		if err != nil {
			continue
		}
		return groups, nil

	}
	if ldapConfig.LDAPTargetURLs == "" {
		var emptyGroup []string
		return emptyGroup, nil
	}
	err := errors.New("error getting the groups")
	return nil, err
}

func (state *RuntimeState) postAuthX509CertHandler(
	w http.ResponseWriter, r *http.Request, targetUser string,
	keySigner crypto.Signer, duration time.Duration,
	withUserGroups bool) {

	var userGroups []string
	var err error
	if withUserGroups {
		userGroups, err = state.getUserGroups(targetUser)
		if err != nil {
			//logger.Println("error getting user groups")
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
		//logger.Printf("%v", userGroups)
	} else {
		userGroups = append(userGroups, "keymaster")
	}
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
		derCert, err := certgen.GenUserX509Cert(targetUser, userPub, caCert, keySigner, state.KerberosRealm, duration, &userGroups)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			logger.Printf("Cannot Generate x509cert")
			return
		}
		eventNotifier.PublishX509(derCert)
		cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert}))

	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return

	}
	metricLogCertDuration("x509", "granted", float64(duration.Seconds()))

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
	state.signerPublicKeyToKeymasterKeys()
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
		state.writeHTMLLoginPage(w, r, profilePath)
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

func (state *RuntimeState) userHasU2FTokens(username string) (bool, error) {
	profile, ok, _, err := state.LoadUserProfile(username)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	registrations := getRegistrationArray(profile.U2fAuthData)
	if len(registrations) < 1 {
		return false, nil
	}
	return true, nil

}

const authCookieName = "auth_cookie"
const randomStringEntropyBytes = 32
const maxAgeSecondsAuthCookie = 57600

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
		logger.Debugf(3, "Got client GET connection")
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	case "POST":
		logger.Debugf(3, "Got client POST connection")
		//err := r.ParseMultipartForm(1e7)
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
		logger.Debugf(2, "req =%+v", r)
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

	valid, err := checkUserPassword(username, password, state.Config, state.passwordChecker, r)
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

	// AUTHN has passed
	logger.Debug(1, "Valid passwd AUTH login for %s", username)
	userHasU2FTokens, err := state.userHasU2FTokens(username)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "error internal")
		logger.Println(err)
		return
	}

	//
	_, err = state.setNewAuthCookie(w, username, AuthTypePassword)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "error internal")
		logger.Println(err)
		return
	}

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
		if certPref == proto.AuthTypeU2F && userHasU2FTokens {
			certBackends = append(certBackends, proto.AuthTypeU2F)
		}
		if certPref == proto.AuthTypeSymantecVIP && state.Config.SymantecVIP.Enabled {
			certBackends = append(certBackends, proto.AuthTypeSymantecVIP)
		}
	}
	// logger.Printf("current backends=%+v", certBackends)
	if len(certBackends) == 0 {
		certBackends = append(certBackends, proto.AuthTypeU2F)
	}

	// TODO: The cert backend should depend also on per user preferences.
	loginResponse := proto.LoginResponse{Message: "success",
		CertAuthBackend: certBackends}
	switch returnAcceptType {
	case "text/html":
		loginDestination := profilePath
		if r.Form.Get("login_destination") != "" {
			loginDestination = r.Form.Get("login_destination")
		}

		requiredAuth := state.getRequiredWebUIAuthLevel()
		if (requiredAuth & AuthTypePassword) != 0 {
			http.Redirect(w, r, loginDestination, 302)
		} else {
			//Go 2FA
			state.writeHTML2FAAuthPage(w, r, loginDestination)
		}
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
	//TODO: check for CSRF (simple way: makeit post only)

	// We first check for cookies
	var authCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		authCookie = cookie
	}

	if authCookie != nil {
		expiration := time.Unix(0, 0)
		updatedAuthCookie := http.Cookie{Name: authCookieName, Value: "", Expires: expiration, Path: "/", HttpOnly: true, Secure: true}
		http.SetCookie(w, &updatedAuthCookie)
	}
	//redirect to login
	http.Redirect(w, r, "/", 302)
}

///
const vipAuthPath = "/api/v0/vipAuth"

func (state *RuntimeState) VIPAuthHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	//Check for valid method here?
	switch r.Method {
	case "GET":
		logger.Debugf(3, "Got client GET connection")
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	case "POST":
		logger.Debugf(3, "Got client POST connection")
		err := r.ParseForm()
		if err != nil {
			logger.Println(err)
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
			return
		}
	default:
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	//authUser, authType, err := state.checkAuth(w, r, AuthTypeAny)
	authUser, currentAuthLevel, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Printf("%v", err)

		return
	}

	var OTPString string
	if val, ok := r.Form["OTP"]; ok {
		if len(val) > 1 {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Just one OTP Value allowed")
			logger.Printf("Login with multiple OTP Values")
			return
		}
		OTPString = val[0]
	}
	otpValue, err := strconv.Atoi(OTPString)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing OTP value")
	}

	start := time.Now()
	valid, err := state.Config.SymantecVIP.Client.ValidateUserOTP(authUser, otpValue)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating VIP token")
		return
	}

	metricLogExternalServiceDuration("vip", time.Since(start))

	//
	metricLogAuthOperation(getClientType(r), proto.AuthTypeSymantecVIP, valid)

	if !valid {
		logger.Printf("Invalid OTP value login for %s", authUser)
		// TODO if client is html then do a redirect back to vipLoginPage
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		return

	}

	// OTP check was  successful
	_, err = state.updateAuthCookieAuthlevel(w, r, currentAuthLevel|AuthTypeSymantecVIP)
	if err != nil {
		logger.Printf("Autch Cookie NOT found ? %s", err)
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure when validating VIP token")
		return
	}

	// Now we send to the appropiate place
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

	// TODO: The cert backend should depend also on per user preferences.
	loginResponse := proto.LoginResponse{Message: "success"} //CertAuthBackend: certBackends
	switch returnAcceptType {
	case "text/html":
		loginDestination := profilePath
		if r.Form.Get("login_destination") != "" {
			loginDestination = r.Form.Get("login_destination")
		}
		http.Redirect(w, r, loginDestination, 302)
	default:
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(loginResponse)
		//fmt.Fprintf(w, "Success!")
	}
	return
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

const u2fRegustisterRequestPath = "/u2f/RegisterRequest/"

func (state *RuntimeState) u2fRegisterRequest(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// /u2f/RegisterRequest/<assumed user>
	// pieces[0] == "" pieces[1] = "u2f" pieces[2] == "RegisterRequest"
	pieces := strings.Split(r.URL.Path, "/")

	var assumedUser string
	if len(pieces) >= 4 {
		assumedUser = pieces[3]
	} else {
		http.Error(w, "error", http.StatusBadRequest)
		return
	}

	/*

		/*
	*/
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, loginLevel, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Printf("%v", err)

		return
	}

	// Check that they can change other users
	if !state.IsAdminUserAndU2F(authUser, loginLevel) && authUser != assumedUser {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
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
	err = state.SaveUserProfile(assumedUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(req)
}

const u2fRegisterRequesponsePath = "/u2f/RegisterResponse/"

func (state *RuntimeState) u2fRegisterResponse(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}

	// /u2f/RegisterResponse/<assumed user>
	// pieces[0] == "" pieces[1] = "u2f" pieces[2] == "RegisterResponse"
	pieces := strings.Split(r.URL.Path, "/")

	var assumedUser string
	if len(pieces) >= 4 {
		assumedUser = pieces[3]
	} else {
		http.Error(w, "error", http.StatusBadRequest)
		return
	}

	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, loginLevel, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Printf("%v", err)

		return
	}

	// Check that they can change other users
	if !state.IsAdminUserAndU2F(authUser, loginLevel) && authUser != assumedUser {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var regResp u2f.RegisterResponse
	if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
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
	err = state.SaveUserProfile(assumedUser, profile)
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
	authUser, _, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Printf("%v", err)

		return
	}

	//////////
	profile, ok, _, err := state.LoadUserProfile(authUser)
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

	//save cached copy
	var localAuth localUserData
	localAuth.U2fAuthChallenge = c
	state.Mutex.Lock()
	state.localAuthData[authUser] = localAuth
	state.Mutex.Unlock()

	req := c.SignRequest(registrations)
	logger.Debugf(3, "Sign request: %+v", req)

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
	authUser, currentAuthLevel, err := state.checkAuth(w, r, AuthTypeAny)
	if err != nil {
		logger.Printf("%v", err)
		return
	}

	//now the actual work
	var signResp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&signResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	logger.Printf("signResponse: %+v", signResp)

	profile, ok, _, err := state.LoadUserProfile(authUser)
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

	if registrations == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}
	state.Mutex.Lock()
	localAuth, ok := state.localAuthData[authUser]
	state.Mutex.Unlock()
	if !ok {
		http.Error(w, "challenge missing", http.StatusBadRequest)
		return
	}

	//var err error
	for i, u2fReg := range profile.U2fAuthData {
		//newCounter, authErr := u2fReg.Registration.Authenticate(signResp, *profile.U2fAuthChallenge, u2fReg.Counter)
		newCounter, authErr := u2fReg.Registration.Authenticate(signResp, *localAuth.U2fAuthChallenge, u2fReg.Counter)
		if authErr == nil {
			metricLogAuthOperation(getClientType(r), proto.AuthTypeU2F, true)

			logger.Printf("newCounter: %d", newCounter)
			//counter = newCounter
			u2fReg.Counter = newCounter
			//profile.U2fAuthData[i].Counter = newCounter
			u2fReg.Counter = newCounter
			profile.U2fAuthData[i] = u2fReg
			//profile.U2fAuthChallenge = nil
			delete(state.localAuthData, authUser)

			_, err = state.updateAuthCookieAuthlevel(w, r, currentAuthLevel|AuthTypeU2F)
			if err != nil {
				logger.Printf("Autch Cookie NOT found ? %s", err)
				state.writeFailureResponse(w, r, http.StatusInternalServerError, "Failure updating vip token")
				return
			}

			// TODO: update local cookie state
			w.Write([]byte("success"))
			return
		}
	}
	metricLogAuthOperation(getClientType(r), proto.AuthTypeU2F, false)

	logger.Printf("VerifySignResponse error: %v", err)
	http.Error(w, "error verifying response", http.StatusInternalServerError)
}

func (state *RuntimeState) IsAdminUser(user string) bool {
	for _, adminUser := range state.Config.Base.AdminUsers {
		if user == adminUser {
			return true
		}
	}
	return false
}

func (state *RuntimeState) IsAdminUserAndU2F(user string, loginLevel int) bool {
	return state.IsAdminUser(user) && ((loginLevel & AuthTypeU2F) != 0)
}

const usersPath = "/users/"

func (state *RuntimeState) usersHandler(
	w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	authUser, _, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Printf("%v", err)

		return
	}

	users, _, err := state.GetUsers()
	if err != nil {
		logger.Printf("Getting users error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}

	JSSources := []string{"/static/jquery-1.12.4.patched.min.js"}

	displayData := usersPageTemplateData{
		AuthUsername: authUser,
		Title:        "Keymaster Users",
		Users:        users,
		JSSources:    JSSources}
	err = state.htmlTemplate.ExecuteTemplate(w, "usersPage", displayData)
	if err != nil {
		logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

const profilePath = "/profile/"

func profileURI(authUser, assumedUser string) string {
	if authUser == assumedUser {
		return profilePath
	}
	return profilePath + assumedUser
}

func (state *RuntimeState) profileHandler(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	// /profile/<assumed user>
	// pieces[0] == "" pieces[1] = "profile" pieces[2] == <assumed user>
	pieces := strings.Split(r.URL.Path, "/")

	var assumedUser string
	if len(pieces) >= 3 {
		assumedUser = pieces[2]
	}

	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, loginLevel, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Printf("%v", err)

		return
	}

	readOnlyMsg := ""
	if assumedUser == "" {
		assumedUser = authUser
	} else if !state.IsAdminUser(authUser) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	} else if (loginLevel & AuthTypeU2F) == 0 {
		readOnlyMsg = "Admins must U2F authenticate to change the profile of others."
	}

	//find the user token
	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		readOnlyMsg = "The active keymaster is running disconnected from its DB backend. All token operations execpt for Authentication cannot proceed."
	}

	JSSources := []string{"/static/jquery-1.12.4.patched.min.js"}
	showU2F := browserSupportsU2F(r)
	if showU2F {
		JSSources = []string{"/static/jquery-1.12.4.patched.min.js", "/static/u2f-api.js", "/static/keymaster-u2f.js"}
	}

	var devices []registeredU2FTokenDisplayInfo
	for i, tokenInfo := range profile.U2fAuthData {

		deviceData := registeredU2FTokenDisplayInfo{
			DeviceData: fmt.Sprintf("%+v", tokenInfo.Registration.AttestationCert.Subject.CommonName),
			Enabled:    tokenInfo.Enabled,
			Name:       tokenInfo.Name,
			Index:      i}
		devices = append(devices, deviceData)
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Name < devices[j].Name {
			return true
		}
		if devices[i].Name > devices[j].Name {
			return false
		}
		return devices[i].DeviceData < devices[j].DeviceData
	})
	displayData := profilePageTemplateData{
		Username:        assumedUser,
		AuthUsername:    authUser,
		Title:           "Keymaster User Profile",
		ShowU2F:         showU2F,
		JSSources:       JSSources,
		ReadOnlyMsg:     readOnlyMsg,
		UsersLink:       state.IsAdminUser(authUser),
		RegisteredToken: devices}
	logger.Debugf(1, "%v", displayData)

	err = state.htmlTemplate.ExecuteTemplate(w, "userProfilePage", displayData)
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
	authUser, loginLevel, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
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
	logger.Debugf(3, "Form: %+v", r.Form)

	assumedUser := r.Form.Get("username")

	// Have admin rights = Must be admin + authenticated with U2F
	hasAdminRights := state.IsAdminUserAndU2F(authUser, loginLevel)

	// Check params
	if !hasAdminRights && assumedUser != authUser {
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
	profile, _, fromCache, err := state.LoadUserProfile(assumedUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
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
		if m, _ := regexp.MatchString("^[-/.a-zA-Z0-9_ ]+$", tokenName); !m {
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

	err = state.SaveUserProfile(assumedUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	// Success!
	returnAcceptType := getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		http.Redirect(w, r, profileURI(authUser, assumedUser), 302)
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
		//landing page
		if r.Method == "GET" && len(r.Cookies()) < 1 {
			state.writeHTMLLoginPage(w, r, profilePath)
			return
		}

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
	prometheus.MustRegister(authOperationCounter)
	prometheus.MustRegister(externalServiceDurationTotal)
	prometheus.MustRegister(certDurationHistogram)
	tricorder.RegisterMetric(
		"keymaster/external-service-duration/LDAP",
		tricorderLDAPExternalServiceDurationTotal,
		units.Millisecond,
		"Time for external LDAP server to perform operation(ms)")
	tricorder.RegisterMetric(
		"keymaster/external-service-duration/VIP",
		tricorderVIPExternalServiceDurationTotal,
		units.Millisecond,
		"Time for external VIP server to perform operation(ms)")
	tricorder.RegisterMetric(
		"keymaster/external-service-duration/storage",
		tricorderStorageExternalServiceDurationTotal,
		units.Millisecond,
		"Time for external Storage server to perform operation(ms)")
}

func main() {
	flag.Usage = Usage
	flag.Parse()

	tricorder.RegisterFlags()
	realLogger := serverlogger.New("")
	logger = realLogger

	if *generateConfig {
		err := generateNewConfig(*configFilename)
		if err != nil {
			panic(err)
		}
		return
	}

	// TODO(rgooch): Pass this in rather than use a global variable.
	eventNotifier = eventnotifier.New(logger)
	runtimeState, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		panic(err)
	}
	logger.Debugf(3, "After load verify")

	adminDashboard := newAdminDashboard(realLogger)
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
	serviceMux.HandleFunc(usersPath, runtimeState.usersHandler)

	serviceMux.HandleFunc(idpOpenIDCConfigurationDocumentPath, runtimeState.idpOpenIDCDiscoveryHandler)
	serviceMux.HandleFunc(idpOpenIDCJWKSPath, runtimeState.idpOpenIDCJWKSHandler)
	serviceMux.HandleFunc(idpOpenIDCAuthorizationPath, runtimeState.idpOpenIDCAuthorizationHandler)
	serviceMux.HandleFunc(idpOpenIDCTokenPath, runtimeState.idpOpenIDCTokenHandler)
	serviceMux.HandleFunc(idpOpenIDCUserinfoPath, runtimeState.idpOpenIDCUserinfoHandler)

	staticFilesPath := filepath.Join(runtimeState.Config.Base.SharedDataDirectory, "static_files")
	serviceMux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticFilesPath))))
	customWebResourcesPath := filepath.Join(runtimeState.Config.Base.SharedDataDirectory, "customization_data", "web_resources")
	if _, err = os.Stat(customWebResourcesPath); err == nil {
		serviceMux.Handle("/custom_static/", http.StripPrefix("/custom_static/", http.FileServer(http.Dir(customWebResourcesPath))))
	}
	serviceMux.HandleFunc(u2fRegustisterRequestPath, runtimeState.u2fRegisterRequest)
	serviceMux.HandleFunc(u2fRegisterRequesponsePath, runtimeState.u2fRegisterResponse)
	serviceMux.HandleFunc(u2fSignRequestPath, runtimeState.u2fSignRequest)
	serviceMux.HandleFunc(u2fSignResponsePath, runtimeState.u2fSignResponse)
	serviceMux.HandleFunc(vipAuthPath, runtimeState.VIPAuthHandler)
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
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	srpc.RegisterServerTlsConfig(
		&tls.Config{ClientCAs: runtimeState.ClientCAPool},
		true)
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
		panic("got bad signer ready data")
	}
	serviceTLSConfig := cfg
	serviceTLSConfig.ClientAuth = tls.RequestClientCert

	serviceSrv := &http.Server{
		Addr:         runtimeState.Config.Base.HttpAddress,
		Handler:      serviceMux,
		TLSConfig:    serviceTLSConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	http.Handle(eventmon.HttpPath, eventNotifier)
	go func() {
		time.Sleep(time.Millisecond * 10)
		healthserver.SetReady()
	}()
	err = serviceSrv.ListenAndServeTLS(
		runtimeState.Config.Base.TLSCertFilename,
		runtimeState.Config.Base.TLSKeyFilename)
	if err != nil {
		panic(err)
	}
}
