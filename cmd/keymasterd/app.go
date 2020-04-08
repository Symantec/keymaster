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
	stdlog "log"
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
	"github.com/Symantec/Dominator/lib/logbuf"
	"github.com/Symantec/Dominator/lib/srpc"
	"github.com/Symantec/keymaster/keymasterd/admincache"
	"github.com/Symantec/keymaster/keymasterd/eventnotifier"
	"github.com/Symantec/keymaster/lib/authutil"
	"github.com/Symantec/keymaster/lib/certgen"
	"github.com/Symantec/keymaster/lib/instrumentedwriter"
	"github.com/Symantec/keymaster/lib/pwauth"
	"github.com/Symantec/keymaster/lib/webapi/v0/proto"
	"github.com/Symantec/keymaster/proto/eventmon"
	"github.com/Symantec/tricorder/go/healthserver"
	"github.com/Symantec/tricorder/go/tricorder"
	"github.com/Symantec/tricorder/go/tricorder/units"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tstranex/u2f"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/net/context"
)

const (
	AuthTypeNone     = 0
	AuthTypePassword = 1 << iota
	AuthTypeFederated
	AuthTypeU2F
	AuthTypeSymantecVIP
	AuthTypeIPCertificate
	AuthTypeTOTP
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

type storageStringDataJWT struct {
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
	Expiration int64    `json:"exp"`
	IssuedAt   int64    `json:"iat,omitempty"`
	TokenType  string   `json:"token_type"`
	DataType   int      `json:"data_type"`
	Data       string   `json:"data"`
}

type u2fAuthData struct {
	Enabled      bool
	CreatedAt    time.Time
	CreatorAddr  string
	Counter      uint32
	Name         string
	Registration *u2f.Registration
}

type totpAuthData struct {
	Enabled         bool
	CreatedAt       time.Time
	Name            string
	EncryptedSecret [][]byte
	TOTPType        int
	ValidatorAddr   string
}

type userProfile struct {
	U2fAuthData           map[int64]*u2fAuthData
	RegistrationChallenge *u2f.Challenge
	//U2fAuthChallenge      *u2f.Challenge
	PendingTOTPSecret          *[][]byte
	LastSuccessfullTOTPCounter int64
	TOTPAuthData               map[int64]*totpAuthData
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

type pushPollTransaction struct {
	ExpiresAt     time.Time
	Username      string
	TransactionID string
}

type totpRateLimitInfo struct {
	lastCheckTime         time.Time
	failCount             uint32
	lastFailTime          time.Time
	lockoutExpirationTime time.Time
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
	vipPushCookie map[string]pushPollTransaction
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
	isAdminCache         *admincache.Cache

	totpLocalRateLimit      map[string]totpRateLimitInfo
	totpLocalTateLimitMutex sync.Mutex
}

const redirectPath = "/auth/oauth2/callback"
const secsBetweenCleanup = 30
const maxAgeU2FVerifySeconds = 30

var (
	Version        = ""
	configFilename = flag.String("config", "/etc/keymaster/config.yml",
		"The filename of the configuration")
	generateConfig = flag.Bool("generateConfig", false,
		"Generate new valid configuration")
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

		for key, vipCookie := range state.vipPushCookie {
			if vipCookie.ExpiresAt.Before(time.Now()) {
				delete(state.vipPushCookie, key)
			}

		}

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
		if len(config.Ldap.LDAPTargetURLs) > 0 {
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
				logger.Debugf(1, "Got it  %+v", acceptValue)
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
		strings.Contains(r.UserAgent(), "Firefox/6") ||
		strings.Contains(r.UserAgent(), "Firefox/7") ||
		strings.Contains(r.UserAgent(), "Firefox/8") {
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
	loginDestination string, tryShowU2f bool) error {
	JSSources := []string{"/static/jquery-3.4.1.min.js", "/static/u2f-api.js"}
	showU2F := browserSupportsU2F(r) && tryShowU2f
	if showU2F {

		JSSources = append(JSSources, "/static/webui-2fa-u2f.js")
	}
	if state.Config.SymantecVIP.Enabled {
		JSSources = append(JSSources, "/static/webui-2fa-symc-vip.js")
	}
	displayData := secondFactorAuthTemplateData{
		Title:            "Keymaster 2FA Auth",
		JSSources:        JSSources,
		ShowVIP:          state.Config.SymantecVIP.Enabled,
		ShowU2F:          showU2F,
		ShowTOTP:         state.Config.Base.EnableLocalTOTP,
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
	loginDestination string, errorMessage string) error {
	//footerText := state.getFooterText()
	displayData := loginPageTemplateData{
		Title:            "Keymaster Login (Use Okta ID/Password)",
		ShowOauth2:       state.Config.Oauth2.Enabled,
		HideStdLogin:     state.Config.Base.HideStandardLogin,
		LoginDestination: loginDestination,
		ErrorMessage:     errorMessage}
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
	setSecurityHeaders(w)
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
					loginDestnation = getLoginDestination(r)
				}
			}
			if authCookie == nil {
				// TODO: change by a message followed by an HTTP redirection
				state.writeHTMLLoginPage(w, r, loginDestnation, message)
				return
			}
			info, err := state.getAuthInfoFromAuthJWT(authCookie.Value)
			if err != nil {
				logger.Debugf(3, "write failure state, error from getinfo authInfoJWT")
				state.writeHTMLLoginPage(w, r, loginDestnation, "")
				return
			}
			if info.ExpiresAt.Before(time.Now()) {
				state.writeHTMLLoginPage(w, r, loginDestnation, "")
				return
			}
			if (info.AuthType & AuthTypePassword) == AuthTypePassword {
				state.writeHTML2FAAuthPage(w, r, loginDestnation, true)
				return
			}
			state.writeHTMLLoginPage(w, r, loginDestnation, message)
			return

		default:
			w.Write([]byte(publicErrorText))
		}
	default:
		w.Write([]byte(publicErrorText))
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	//all common security headers go here
	w.Header().Set("Strict-Transport-Security", "max-age=1209600")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1")
	w.Header().Set("Content-Security-Policy", "default-src 'self' ;style-src 'self' fonts.googleapis.com 'unsafe-inline'; font-src fonts.gstatic.com fonts.googleapis.com")
}

// returns true if the system is locked and sends message to the requester
func (state *RuntimeState) sendFailureToClientIfLocked(w http.ResponseWriter, r *http.Request) bool {
	var signerIsNull bool

	state.Mutex.Lock()
	signerIsNull = (state.Signer == nil)
	state.Mutex.Unlock()

	setSecurityHeaders(w)

	if signerIsNull {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		logger.Printf("Signer has not been unlocked")
		return true
	}
	return false
}

func (state *RuntimeState) setNewAuthCookie(w http.ResponseWriter, username string, authlevel int) (string, error) {

	attribs, err := state.getUserAttributesOkta(username, []string{"uid"})

	if err != nil {
		logger.Printf("Err[%s] getUserAttributesOkta(%s)", err.Error(), username)
	} else {
		uid, ok := attribs["uid"]
		if ok && len(uid) > 0 {
			// username = strings.Join([]string{uid[0], username}, ":")
			username = uid[0]
		}
	}

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
func (state *RuntimeState) isAutomationUser(username string) (bool, error) {
	for _, automationUsername := range state.Config.Base.AutomationUsers {
		if automationUsername == username {
			return true, nil
		}
	}
	userGroups, err := state.getUserGroups(username)
	if err != nil {
		return false, err
	}
	for _, automationGroup := range state.Config.Base.AutomationUserGroups {
		for _, groupName := range userGroups {
			if groupName == automationGroup {
				return true, nil
			}
		}
	}
	return false, nil
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
	// We first check for certs if this auth is allowed
	if ((requiredAuthType & AuthTypeIPCertificate) == AuthTypeIPCertificate) &&
		r.TLS != nil {
		logger.Debugf(3, "looks like authtype ip cert, r.tls=%+v", r.TLS)
		if len(r.TLS.VerifiedChains) > 0 {
			logger.Debugf(3, "looks like authtype ip cert, has verifiedChains")
			clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
			userCert := r.TLS.VerifiedChains[0][0]

			validIP, err := certgen.VerifyIPRestrictedX509CertIP(userCert, r.RemoteAddr)
			if err != nil {
				logger.Printf("Error verifying up restricted cert: %s", err)
				state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
				return "", AuthTypeNone, fmt.Errorf("checkAuth: Error verifying IP restricted cert: %s", err)
			}
			if !validIP {
				logger.Printf("Invalid IP for cert: %s is not valid for incoming connection", r.RemoteAddr)
				state.writeFailureResponse(w, r, http.StatusUnauthorized, "Bad incoming ip address")
				return "", AuthTypeNone, fmt.Errorf("checkAuth: Error verifying IP restricted cert. Invalid incoming address: %s", r.RemoteAddr)
			}
			// Check if there are group restrictions on
			ok, err := state.isAutomationUser(clientName)
			if err != nil {
				state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
				return "", AuthTypeNone, fmt.Errorf("checkAuth: Error checking user permissions for automation certs : %s", err)
			}
			if !ok {
				state.writeFailureResponse(w, r, http.StatusUnauthorized, "Bad username  for ip restricted cert ")
				return "", AuthTypeNone, fmt.Errorf("checkAuth: User %s is not a service account.", clientName)
			}

			revoked, ok, err := revoke.VerifyCertificateError(userCert)
			if err != nil {
				logger.Printf("Error checking revocation of IP  restricted cert: %s", err)
			}
			// Soft Fail: we only fail if the revocation check was successful and the cert is revoked
			if revoked == true && ok {
				logger.Printf("Cert is revoked")
				state.writeFailureResponse(w, r, http.StatusUnauthorized, "revoked Cert")
				return "", AuthTypeNone, fmt.Errorf("checkAuth: IP cert is revoked")
			}
			return clientName, AuthTypeIPCertificate, nil

		}
	}

	// Next we check for cookies
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
		if !state.Config.Base.DisableUsernameNormalization {
			user = strings.ToLower(user)
		}
		valid, err := checkUserPassword(user, pass, config, state.passwordChecker, r)
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return "", AuthTypeNone, err
		}
		if !valid {
			state.writeFailureResponse(w, r, http.StatusUnauthorized, "Invalid Username/Password")
			err := errors.New("Invalid Credentials")
			return "", AuthTypeNone, err
		}
		attribs, err := state.getUserAttributesOkta(user, []string{"uid"})
		if err != nil {
			logger.Printf("Err[%s] getUserAttributesOkta(%s)", err.Error(), user)
		} else {
			uid, ok := attribs["uid"]
			if ok && len(uid) > 0 {
				// user = strings.Join([]string{uid[0], user}, ":")
				user = uid[0]
			}
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
		if webUIPref == proto.AuthTypeTOTP {
			AuthLevel |= AuthTypeTOTP
		}
	}
	return AuthLevel
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
		setSecurityHeaders(w)
		state.writeHTMLLoginPage(w, r, profilePath, "")
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
const vipTransactionCookieName = "vip_push_cookie"
const maxAgeSecondsVIPCookie = 120
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

// We need to ensure that all login destinations are relative paths
// Thus the path MUST start with a / but MUST NOT start with a //, because
// // is interpreted as: use whatever protocol you think is OK
func getLoginDestination(r *http.Request) string {
	loginDestination := profilePath
	if r.Form.Get("login_destination") != "" {
		inboundLoginDestination := r.Form.Get("login_destination")
		if strings.HasPrefix(inboundLoginDestination, "/") &&
			!strings.HasPrefix(inboundLoginDestination, "//") {
			loginDestination = inboundLoginDestination
		}
	}
	return loginDestination
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

	if !state.Config.Base.DisableUsernameNormalization {
		username = strings.ToLower(username)
	}
	valid, err := checkUserPassword(username, password, state.Config, state.passwordChecker, r)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if !valid {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "Invalid Username/Password")
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
	eventNotifier.PublishAuthEvent(eventmon.AuthTypePassword, username)

	returnAcceptType := "application/json"
	acceptHeader, ok := r.Header["Accept"]
	if ok {
		for _, acceptValue := range acceptHeader {
			if strings.Contains(acceptValue, "text/html") {
				logger.Debugf(1, "Got it  %+v", acceptValue)
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
		if certPref == proto.AuthTypeTOTP && state.Config.Base.EnableLocalTOTP {
			certBackends = append(certBackends, proto.AuthTypeTOTP)
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
		loginDestination := getLoginDestination(r)
		requiredAuth := state.getRequiredWebUIAuthLevel()
		if (requiredAuth & AuthTypePassword) != 0 {
			eventNotifier.PublishWebLoginEvent(username)
			http.Redirect(w, r, loginDestination, 302)
		} else {
			//Go 2FA
			if (requiredAuth & AuthTypeSymantecVIP) == AuthTypeSymantecVIP {
				// set VIP cookie
				cookieValue, err := genRandomString()
				if err == nil { //Beware inverted Logic

					expiration := time.Now().Add(maxAgeSecondsVIPCookie * time.Second)
					vipPushCookie := http.Cookie{Name: vipTransactionCookieName,
						Value: cookieValue, Expires: expiration,
						Path: "/", HttpOnly: true, Secure: true}
					http.SetCookie(w, &vipPushCookie)
				}
			}
			state.writeHTML2FAAuthPage(w, r, loginDestination, userHasU2FTokens)
		}
	default:
		// add vippush cookie if we are using VIP
		usesVIP := false
		for _, certPref := range state.Config.Base.AllowedAuthBackendsForCerts {
			if certPref == proto.AuthTypeSymantecVIP && state.Config.SymantecVIP.Enabled {
				usesVIP = true
			}
		}
		requiredWebAuth := state.getRequiredWebUIAuthLevel()
		usesVIP = usesVIP || ((requiredWebAuth & AuthTypeSymantecVIP) == AuthTypeSymantecVIP)
		if usesVIP {
			cookieValue, err := genRandomString()
			if err == nil { //Beware inverted Logic
				expiration := time.Now().Add(maxAgeSecondsVIPCookie * time.Second)
				vipPushCookie := http.Cookie{Name: vipTransactionCookieName,
					Value: cookieValue, Expires: expiration,
					Path: "/", HttpOnly: true, Secure: true}
				http.SetCookie(w, &vipPushCookie)
			}
		}

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

func (state *RuntimeState) _IsAdminUser(user string) (bool, error) {
	for _, adminUser := range state.Config.Base.AdminUsers {
		if user == adminUser {
			return true, nil
		}
	}
	if len(state.Config.Base.AdminGroups) > 0 {
		groups, err := state.getUserGroups(user)
		if err != nil {
			return false, err
		}
		// Store groups to which this user belongs in a set.
		userGroupSet := make(map[string]struct{})
		for _, group := range groups {
			userGroupSet[group] = struct{}{}
		}
		// Check each admin group from config file.
		// If user belongs to one of these groups then they are an admin
		// user.
		for _, adminGroup := range state.Config.Base.AdminGroups {
			if _, ok := userGroupSet[adminGroup]; ok {
				return true, nil
			}
		}
	}
	return false, nil
}

func (state *RuntimeState) IsAdminUser(user string) bool {
	isAdmin, valid := state.isAdminCache.Get(user)

	// If cached entry is valid, return it as is.
	if valid {
		return isAdmin
	}

	// Entry has expired, do expensive _IsAdminUser call
	newIsAdmin, err := state._IsAdminUser(user)
	if err == nil {

		// On success, cache and return result
		state.isAdminCache.Put(user, newIsAdmin)
		return newIsAdmin
	}
	// Otherwise, re-cache and return previously cached value
	state.isAdminCache.Put(user, isAdmin)
	return isAdmin
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
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)

	users, _, err := state.GetUsers()
	if err != nil {
		logger.Printf("Getting users error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}

	JSSources := []string{"/static/jquery-3.4.1.min.js"}

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
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)

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

	JSSources := []string{"/static/jquery-3.4.1.min.js"}
	showU2F := browserSupportsU2F(r)
	if showU2F {
		JSSources = append(JSSources, "/static/u2f-api.js", "/static/keymaster-u2f.js")
	}

	// TODO: move deviceinfo mapping/sorting to its own function
	var u2fdevices []registeredU2FTokenDisplayInfo
	for i, tokenInfo := range profile.U2fAuthData {
		deviceData := registeredU2FTokenDisplayInfo{
			DeviceData: fmt.Sprintf("%+v", tokenInfo.Registration.AttestationCert.Subject.CommonName),
			Enabled:    tokenInfo.Enabled,
			Name:       tokenInfo.Name,
			Index:      i}
		u2fdevices = append(u2fdevices, deviceData)
	}
	sort.Slice(u2fdevices, func(i, j int) bool {
		if u2fdevices[i].Name < u2fdevices[j].Name {
			return true
		}
		if u2fdevices[i].Name > u2fdevices[j].Name {
			return false
		}
		return u2fdevices[i].DeviceData < u2fdevices[j].DeviceData
	})
	var totpdevices []registeredTOTPTDeviceDisplayInfo
	for i, deviceInfo := range profile.TOTPAuthData {
		deviceData := registeredTOTPTDeviceDisplayInfo{
			Enabled: deviceInfo.Enabled,
			Name:    deviceInfo.Name,
			Index:   i,
		}
		totpdevices = append(totpdevices, deviceData)
	}
	showTOTP := state.Config.Base.EnableLocalTOTP

	displayData := profilePageTemplateData{
		Username:             assumedUser,
		AuthUsername:         authUser,
		Title:                "Keymaster User Profile",
		ShowU2F:              showU2F,
		JSSources:            JSSources,
		ReadOnlyMsg:          readOnlyMsg,
		UsersLink:            state.IsAdminUser(authUser),
		RegisteredU2FToken:   u2fdevices,
		ShowTOTP:             showTOTP,
		RegisteredTOTPDevice: totpdevices,
	}
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
		logger.Debugf(1, "%v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
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
	setSecurityHeaders(w)
	if r.URL.Path == "/favicon.ico" {
		w.Header().Set("Cache-Control", "public, max-age=120")
		http.Redirect(w, r, "/static/favicon.ico", http.StatusFound)
		return
	}
	//redirect to profile
	if r.URL.Path[:] == "/" {
		//landing page
		if r.Method == "GET" && len(r.Cookies()) < 1 {
			state.writeHTMLLoginPage(w, r, profilePath, "")
			return
		}

		http.Redirect(w, r, profilePath, 302)
		return
	}
	http.Error(w, "error not found", http.StatusNotFound)
}

type httpLogger struct {
	AccessLogger log.DebugLogger
}

func (l httpLogger) Log(record instrumentedwriter.LogRecord) {
	if l.AccessLogger != nil {
		l.AccessLogger.Printf("%s -  %s [%s] \"%s %s %s\" %d %d \"%s\"\n",
			record.Ip, record.Username, record.Time, record.Method,
			record.Uri, record.Protocol, record.Status, record.Size, record.UserAgent)
	}
}

func Usage() {
	displayVersion := Version
	if Version == "" {
		displayVersion = "No version provided"
	}
	fmt.Fprintf(os.Stderr, "Usage of %s (version %s):\n", os.Args[0], displayVersion)
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
		logger.Println(err)
		os.Exit(1)
	}
	logger.Debugf(3, "After load verify")

	publicLogs := runtimeState.Config.Base.PublicLogs
	adminDashboard := newAdminDashboard(realLogger, publicLogs)

	logBufOptions := logbuf.GetStandardOptions()
	accessLogDirectory := filepath.Join(logBufOptions.Directory, "access")
	logger.Debugf(1, "acesslogdir=%d ", accessLogDirectory)
	serviceAccessLogger := serverlogger.NewWithOptions("access",
		logbuf.Options{MaxFileSize: 10 << 20,
			Quota: 100 << 20, MaxBufferLines: 100,
			Directory: accessLogDirectory},
		stdlog.LstdFlags)

	adminAccesLogDirectory := filepath.Join(logBufOptions.Directory, "access-admin")
	adminAccessLogger := serverlogger.NewWithOptions("access-admin",
		logbuf.Options{MaxFileSize: 10 << 20,
			Quota: 100 << 20, MaxBufferLines: 100,
			Directory: adminAccesLogDirectory},
		stdlog.LstdFlags)

	// Expose the registered metrics via HTTP.
	http.Handle("/", adminDashboard)
	http.Handle("/prometheus_metrics", promhttp.Handler()) //lint:ignore SA1019 TODO: newer prometheus handler
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
	serviceMux.HandleFunc(vipPushStartPath, runtimeState.vipPushStartHandler)
	serviceMux.HandleFunc(vipPollCheckPath, runtimeState.VIPPollCheckHandler)
	serviceMux.HandleFunc(totpGeneratNewPath, runtimeState.GenerateNewTOTP)
	serviceMux.HandleFunc(totpValidateNewPath, runtimeState.validateNewTOTP)
	serviceMux.HandleFunc(totpTokenManagementPath, runtimeState.totpTokenManagerHandler)
	serviceMux.HandleFunc(totpVerifyHandlerPath, runtimeState.verifyTOTPHandler)
	serviceMux.HandleFunc(totpAuthPath, runtimeState.TOTPAuthHandler)

	serviceMux.HandleFunc("/", runtimeState.defaultPathHandler)

	cfg := &tls.Config{
		ClientCAs:                runtimeState.ClientCAPool,
		ClientAuth:               tls.VerifyClientCertIfGiven,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	logFilterHandler := NewLogFilterHandler(http.DefaultServeMux, publicLogs)
	serviceHTTPLogger := httpLogger{AccessLogger: serviceAccessLogger}
	adminHTTPLogger := httpLogger{AccessLogger: adminAccessLogger}
	adminSrv := &http.Server{
		Addr:         runtimeState.Config.Base.AdminAddress,
		TLSConfig:    cfg,
		Handler:      instrumentedwriter.NewLoggingHandler(logFilterHandler, adminHTTPLogger),
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

	if len(runtimeState.Config.Ldap.LDAPTargetURLs) > 0 && !runtimeState.Config.Ldap.DisablePasswordCache {
		err = runtimeState.passwordChecker.UpdateStorage(runtimeState)
		if err != nil {
			logger.Fatalf("Cannot update password checker")
		}
	}

	// Safari in MacOS 10.12.x required a cert to be presented by the user even
	// when optional.
	// Our usage shows this is less than 1% of users so we are now mandating
	// verification on issues we will need to update clientAuth back  to tls.RequestClientCert
	serviceTLSConfig := &tls.Config{
		ClientCAs:                runtimeState.ClientCAPool,
		ClientAuth:               tls.VerifyClientCertIfGiven,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	serviceSrv := &http.Server{
		Addr:         runtimeState.Config.Base.HttpAddress,
		Handler:      instrumentedwriter.NewLoggingHandler(serviceMux, serviceHTTPLogger),
		TLSConfig:    serviceTLSConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	http.Handle(eventmon.HttpPath, eventNotifier)
	go func() {
		time.Sleep(time.Millisecond * 10)
		healthserver.SetReady()
		adminDashboard.setReady()
	}()
	err = serviceSrv.ListenAndServeTLS(
		runtimeState.Config.Base.TLSCertFilename,
		runtimeState.Config.Base.TLSKeyFilename)
	if err != nil {
		panic(err)
	}
}
