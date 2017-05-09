package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/Symantec/Dominator/lib/logbuf"
	"github.com/Symantec/keymaster/lib/authutil"
	"github.com/Symantec/keymaster/lib/certgen"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
	//"io"
	"io/ioutil"
	"log"
	//"net"
	"net/http"
	//"net/url"
	"os"
	"regexp"
	//"strconv"
	"strings"
	"sync"
	"time"
)

// describes the network config and the mechanism for user auth.
// While the contents of the certificaes are public, we want to
// restrict generation to authenticated users
type baseConfig struct {
	HttpAddress      string `yaml:"http_address"`
	TLSCertFilename  string `yaml:"tls_cert_filename"`
	TLSKeyFilename   string `yaml:"tls_key_filename"`
	UserAuth         string
	SSHCAFilename    string `yaml:"ssh_ca_filename"`
	HtpasswdFilename string `yaml:"htpasswd_filename"`
	ClientCAFilename string `yaml:"client_ca_filename"`
	HostIdentity     string `yaml:"host_identity"`
	KerberosRealm    string `yaml:"kerberos_realm"`
}

type LdapConfig struct {
	Bind_Pattern     string
	LDAP_Target_URLs string
}

type AppConfigFile struct {
	Base baseConfig
	Ldap LdapConfig
}

type userInfo struct {
	ExpiresAt time.Time
	Username  string
}

type RuntimeState struct {
	Config              AppConfigFile
	SSHCARawFileContent []byte
	Signer              crypto.Signer
	ClientCAPool        *x509.CertPool
	HostIdentity        string
	KerberosRealm       *string
	caCertDer           []byte
	authCookie          map[string]userInfo
	Mutex               sync.Mutex
}

var (
	configFilename = flag.String("config", "config.yml", "The filename of the configuration")
	debug          = flag.Bool("debug", false, "Enable debug messages to console")
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

func loadVerifyConfigFile(configFilename string) (RuntimeState, error) {
	var runtimeState RuntimeState
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return runtimeState, err
	}
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		err = errors.New("cannot read config file")
		return runtimeState, err
	}
	err = yaml.Unmarshal(source, &runtimeState.Config)
	if err != nil {
		err = errors.New("Cannot parse config file")
		return runtimeState, err
	}

	//share config
	runtimeState.authCookie = make(map[string]userInfo)

	//verify config
	if len(runtimeState.Config.Base.HostIdentity) > 0 {
		runtimeState.HostIdentity = runtimeState.Config.Base.HostIdentity
	} else {
		runtimeState.HostIdentity, err = getHostIdentity()
		if err != nil {
			return runtimeState, err
		}
	}
	if len(runtimeState.Config.Base.KerberosRealm) > 0 {
		runtimeState.KerberosRealm = &runtimeState.Config.Base.KerberosRealm
	}

	_, err = exitsAndCanRead(runtimeState.Config.Base.TLSCertFilename, "http cert file")
	if err != nil {
		return runtimeState, err
	}
	_, err = exitsAndCanRead(runtimeState.Config.Base.TLSKeyFilename, "http key file")
	if err != nil {
		return runtimeState, err
	}

	sshCAFilename := runtimeState.Config.Base.SSHCAFilename
	runtimeState.SSHCARawFileContent, err = exitsAndCanRead(sshCAFilename, "ssh CA File")
	if err != nil {
		log.Printf("Cannot load ssh CA File")
		return runtimeState, err
	}

	if len(runtimeState.Config.Base.ClientCAFilename) > 0 {
		clientCAbuffer, err := exitsAndCanRead(runtimeState.Config.Base.ClientCAFilename, "client CA file")
		if err != nil {
			log.Printf("Cannot load client CA File")
			return runtimeState, err
		}
		runtimeState.ClientCAPool = x509.NewCertPool()
		ok := runtimeState.ClientCAPool.AppendCertsFromPEM(clientCAbuffer)
		if !ok {
			err = errors.New("Cannot append any certs from Client CA file")
			return runtimeState, err
		}
		if *debug || true {
			log.Printf("client ca file loaded")
		}

	}
	if strings.HasPrefix(string(runtimeState.SSHCARawFileContent[:]), "-----BEGIN RSA PRIVATE KEY-----") {
		signer, err := getSignerFromPEMBytes(runtimeState.SSHCARawFileContent)
		if err != nil {
			log.Printf("Cannot parse Priave Key file")
			return runtimeState, err
		}
		runtimeState.caCertDer, err = generateCADer(&runtimeState, signer)
		if err != nil {
			log.Printf("Cannot generate CA Der")
			return runtimeState, err
		}

		// Assignmet of signer MUST be the last operation after
		// all error checks
		runtimeState.Signer = signer

	} else {
		if runtimeState.ClientCAPool == nil {
			err := errors.New("Invalid ssh CA private key file and NO clientCA")
			return runtimeState, err
		}
		//check that the loaded date seems like an openpgp armored file
		fileAsString := string(runtimeState.SSHCARawFileContent[:])
		if !strings.HasPrefix(fileAsString, "-----BEGIN PGP MESSAGE-----") {
			err = errors.New("Have a client CA but the CA file does NOT look like and PGP file")
			return runtimeState, err
		}

	}

	return runtimeState, nil
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
			log.Printf("Failed to parse ldapurl '%s'", ldapUrl)
			continue
		}
		vaild, err := authutil.CheckLDAPUserPassword(*u, bindDN, password, timeoutSecs, nil)
		if err != nil {
			//log.Printf("Failed to parse %s", ldapUrl)
			continue
		}
		// the ldap exchange was successful (user might be invaid)
		return vaild, nil

	}
	if config.Base.HtpasswdFilename != "" {
		if *debug {
			log.Printf("I have htpasswed filename")
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

func writeFailureResponse(w http.ResponseWriter, code int, message string) {
	if code == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="User Credentials"`)
	}
	w.WriteHeader(code)
	publicErrorText := fmt.Sprintf("%d %s %s\n", code, http.StatusText(code), message)
	w.Write([]byte(publicErrorText))
}

// Inspired by http://stackoverflow.com/questions/21936332/idiomatic-way-of-requiring-http-basic-auth-in-go
func checkAuth(w http.ResponseWriter, r *http.Request, config AppConfigFile) (string, error) {
	//For now just check http basic
	user, pass, ok := r.BasicAuth()
	if !ok {
		writeFailureResponse(w, http.StatusUnauthorized, "")
		err := errors.New("check_Auth, Invalid or no auth header")
		return "", err
	}
	valid, err := checkUserPassword(user, pass, config)
	if err != nil {
		writeFailureResponse(w, http.StatusInternalServerError, "")
		return "", err
	}
	if !valid {
		writeFailureResponse(w, http.StatusUnauthorized, "")
		err := errors.New("Invalid Credentials")
		return "", err
	}
	return user, nil

}

const CERTGEN_PATH = "/certgen/"

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
		writeFailureResponse(w, http.StatusInternalServerError, "")
		log.Printf("Signer not loaded")
		return
	}
	/*
	 */
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds
	authUser, err := checkAuth(w, r, state.Config)
	if err != nil {
		log.Printf("%v", err)

		return
	}

	targetUser := r.URL.Path[len(CERTGEN_PATH):]
	if authUser != targetUser {
		writeFailureResponse(w, http.StatusForbidden, "")
		log.Printf("User %s asking for creds for %s", authUser, targetUser)
		return
	}
	if *debug {
		log.Printf("auth succedded for %s", authUser)
	}

	switch r.Method {
	case "GET":
		if *debug {
			log.Printf("Got client GET connection")
		}
		err = r.ParseForm()
		if err != nil {
			log.Println(err)
			writeFailureResponse(w, http.StatusBadRequest, "Error parsing form")
			return
		}
	case "POST":
		if *debug {
			log.Printf("Got client POST connection")
		}
		err = r.ParseMultipartForm(1e7)
		if err != nil {
			log.Println(err)
			writeFailureResponse(w, http.StatusBadRequest, "Error parsing form")
			return
		}
	default:
		writeFailureResponse(w, http.StatusMethodNotAllowed, "")
		return
	}

	certType := "ssh"
	if val, ok := r.Form["type"]; ok {
		certType = val[0]
	}
	log.Printf("cert type =%s", certType)

	switch certType {
	case "ssh":
		state.postAuthSSHCertHandler(w, r, targetUser, keySigner)
		return
	case "x509":
		state.postAuthX509CertHandler(w, r, targetUser, keySigner)
		return
	default:
		writeFailureResponse(w, http.StatusBadRequest, "Unrecognized cert type")
		return
	}
	//SHOULD have never reached this!
	writeFailureResponse(w, http.StatusInternalServerError, "")
	log.Printf("Escape from default paths")
	return

}

func (state *RuntimeState) postAuthSSHCertHandler(w http.ResponseWriter, r *http.Request, targetUser string, keySigner crypto.Signer) {
	signer, err := ssh.NewSignerFromSigner(keySigner)
	if err != nil {
		writeFailureResponse(w, http.StatusInternalServerError, "")
		log.Printf("Signer failed to load")
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
			log.Println(err)
			writeFailureResponse(w, http.StatusBadRequest, "Missing public key file")
			return
		}
		defer file.Close()
		buf := new(bytes.Buffer)
		buf.ReadFrom(file)
		userPubKey := buf.String()
		//validKey, err := regexp.MatchString("^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) [a-zA-Z0-9/+]+=?=? .*$", userPubKey)
		validKey, err := regexp.MatchString("^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) [a-zA-Z0-9/+]+=?=? ?.{0,512}\n?$", userPubKey)
		if err != nil {
			log.Println(err)
			writeFailureResponse(w, http.StatusInternalServerError, "")
			return
		}
		if !validKey {
			writeFailureResponse(w, http.StatusBadRequest, "Invalid File, bad re")
			log.Printf("invalid file, bad re")
			return

		}

		cert, err = certgen.GenSSHCertFileString(targetUser, userPubKey, signer, state.HostIdentity)
		if err != nil {
			writeFailureResponse(w, http.StatusInternalServerError, "")
			log.Printf("signUserPubkey Err")
			return
		}

	default:
		writeFailureResponse(w, http.StatusMethodNotAllowed, "")
		return

	}
	w.Header().Set("Content-Disposition", `attachment; filename="id_rsa-cert.pub"`)
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", cert)
	log.Printf("Generated SSH Certifcate for %s", targetUser)

}

func (state *RuntimeState) postAuthX509CertHandler(w http.ResponseWriter, r *http.Request, targetUser string, keySigner crypto.Signer) {
	var cert string
	switch r.Method {
	case "POST":
		file, _, err := r.FormFile("pubkeyfile")
		if err != nil {
			log.Println(err)
			writeFailureResponse(w, http.StatusBadRequest, "Missing public key file")
			return
		}
		defer file.Close()
		buf := new(bytes.Buffer)
		buf.ReadFrom(file)

		block, _ := pem.Decode(buf.Bytes())
		if block == nil || block.Type != "PUBLIC KEY" {
			writeFailureResponse(w, http.StatusBadRequest, "Invalid File, Unable to decode pem")
			log.Printf("invalid file, unable to decode pem")
			return
		}
		userPub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			writeFailureResponse(w, http.StatusBadRequest, "Cannot parse public key")
			log.Printf("Cannot parse public key")
			return
		}
		//tate.caCertDer
		caCert, err := x509.ParseCertificate(state.caCertDer)
		if err != nil {
			//writeFailureResponse(w, http.StatusBadRequest, "Cannot parse public key")
			writeFailureResponse(w, http.StatusInternalServerError, "")
			log.Printf("Cannot parse CA Der data")
			return
		}
		derCert, err := certgen.GenUserX509Cert(targetUser, userPub, caCert, keySigner, state.KerberosRealm)
		if err != nil {
			writeFailureResponse(w, http.StatusInternalServerError, "")
			log.Printf("Cannot Generate x509cert")
			return
		}
		cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert}))

	default:
		writeFailureResponse(w, http.StatusMethodNotAllowed, "")
		return

	}
	w.Header().Set("Content-Disposition", `attachment; filename="userCert.pem"`)
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", cert)
	log.Printf("Generated x509 Certifcate for %s", targetUser)
}

const SECRETINJECTOR_PATH = "/admin/inject"

func (state *RuntimeState) secretInjectorHandler(w http.ResponseWriter, r *http.Request) {
	// checks this is only allowed when using TLS client certs.. all other authn
	// mechanisms are considered invalid... for now no authz mechanisms are in place ie
	// Any user with a valid cert can use this handler
	if r.TLS == nil {
		writeFailureResponse(w, http.StatusInternalServerError, "")
		log.Printf("We require TLS\n")
		return
	}

	if len(r.TLS.VerifiedChains) < 1 {
		writeFailureResponse(w, http.StatusForbidden, "")
		log.Printf("Forbidden\n")
		return
	}
	clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
	log.Printf("Got connection from %s", clientName)
	r.ParseForm()
	sshCAPassword, ok := r.Form["ssh_ca_password"]
	if !ok {
		writeFailureResponse(w, http.StatusBadRequest, "Invalid Post, missing data")
		log.Printf("missing ssh_ca_password")
		return
	}
	state.Mutex.Lock()
	defer state.Mutex.Unlock()

	// TODO.. make network error blocks to goroutines
	if state.Signer != nil {
		writeFailureResponse(w, http.StatusConflict, "Conflict post, signer already unlocked")
		log.Printf("Signer not null, already unlocked")
		return
	}

	decbuf := bytes.NewBuffer(state.SSHCARawFileContent)

	armorBlock, err := armor.Decode(decbuf)
	if err != nil {
		log.Printf("Cannot decode armored file")
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
		log.Printf("cannot read message")
		return
	}

	plaintextBytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return
	}

	signer, err := getSignerFromPEMBytes(plaintextBytes)
	if err != nil {
		log.Printf("Cannot parse Priave Key file")
		return
	}

	log.Printf("About to generate cader %s", clientName)
	state.caCertDer, err = generateCADer(state, signer)
	if err != nil {
		log.Printf("Cannot generate CA Der")
		return
	}

	// Assignmet of signer MUST be the last operation after
	// all error checks
	state.Signer = signer

	// TODO... make success a goroutine
	w.WriteHeader(200)
	fmt.Fprintf(w, "OK\n")
	//fmt.Fprintf(w, "%+v\n", r.TLS)
}

const PUBLIC_PATH = "/public/"

//Should be a template
const loginFormText = `
<html>
    <head>
	<meta charset="UTF-8">
	<title>{{.Title}}</title>
    </head>
    <body>
	<form enctype="application/x-www-form-urlencoded" action="/api/v0/login" method="post">
	    <p>Username: <INPUT TYPE="text" NAME="username" SIZE=18></p>
	    <p>Password: <INPUT TYPE="password" NAME="password" SIZE=18></p>
	    <p><input type="submit" value="Submit" /></p>
	</form>
    </body>
</html>
`

func (state *RuntimeState) publicPathHandler(w http.ResponseWriter, r *http.Request) {
	var signerIsNull bool

	// check if initialized(singer  not nil)
	state.Mutex.Lock()
	signerIsNull = (state.Signer == nil)
	state.Mutex.Unlock()
	if signerIsNull {
		writeFailureResponse(w, http.StatusInternalServerError, "")
		log.Printf("Signer not loaded")
		return
	}

	target := r.URL.Path[len(PUBLIC_PATH):]

	switch target {
	case "loginForm":
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", loginFormText)
		return
	case "x509ca":
		pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: state.caCertDer}))

		w.Header().Set("Content-Disposition", `attachment; filename="id_rsa-cert.pub"`)
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", pemCert)
	default:
		writeFailureResponse(w, http.StatusNotFound, "")
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

const LOGIN_PATH = "/api/v0/login"

func (state *RuntimeState) loginHandler(w http.ResponseWriter, r *http.Request) {
	//log.Printf("Top of LoginHandler")
	signerIsNull := true
	// check if initialized(singer  not nil)
	state.Mutex.Lock()
	signerIsNull = (state.Signer == nil)
	state.Mutex.Unlock()
	if signerIsNull {
		writeFailureResponse(w, http.StatusInternalServerError, "")
		log.Printf("Signer not loaded")
		return
	}

	//Check for valid method here?
	switch r.Method {
	case "GET":
		if *debug {
			log.Printf("Got client GET connection")
		}
		err := r.ParseForm()
		if err != nil {
			log.Println(err)
			writeFailureResponse(w, http.StatusBadRequest, "Error parsing form")
			return
		}
	case "POST":
		if *debug {
			log.Printf("Got client POST connection")
		}
		//err := r.ParseMultipartForm(1e7)
		err := r.ParseForm()
		if err != nil {
			log.Println(err)
			writeFailureResponse(w, http.StatusBadRequest, "Error parsing form")
			return
		}
		//log.Printf("req =%+v", r)
	default:
		writeFailureResponse(w, http.StatusMethodNotAllowed, "")
		return
	}

	//First headers and then check form
	username, password, ok := r.BasicAuth()
	if !ok {
		//var username string
		if val, ok := r.Form["username"]; ok {
			if len(val) > 1 {
				writeFailureResponse(w, http.StatusBadRequest, "Just one username allowed")
				log.Printf("Login with multiple usernames")
				return
			}
			username = val[0]
		}
		//var password string
		if val, ok := r.Form["password"]; ok {
			if len(val) > 1 {
				writeFailureResponse(w, http.StatusBadRequest, "Just one password allowed")
				log.Printf("Login with passwords")
				return
			}
			password = val[0]
		}

		if len(username) < 1 || len(password) < 1 {
			writeFailureResponse(w, http.StatusUnauthorized, "")
			return
		}
	}

	valid, err := checkUserPassword(username, password, state.Config)
	if err != nil {
		writeFailureResponse(w, http.StatusInternalServerError, "")
		return
	}
	if !valid {
		writeFailureResponse(w, http.StatusUnauthorized, "")
		log.Printf("Invalid login for %s", username)
		//err := errors.New("Invalid Credentials")
		return
	}
	//
	cookieVal, err := genRandomString()
	if err != nil {
		writeFailureResponse(w, http.StatusInternalServerError, "error internal")
		log.Println(err)
		return
	}

	expiration := time.Now().Add(time.Duration(maxAgeSecondsAuthCookie) * time.Second)
	savedUserInfo := userInfo{Username: username, ExpiresAt: expiration}
	state.Mutex.Lock()
	state.authCookie[cookieVal] = savedUserInfo
	state.Mutex.Unlock()

	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal, Expires: expiration, Path: "/", HttpOnly: true, Secure: true}

	//use handler with original request.
	http.SetCookie(w, &authCookie)

	//return user, nil

	//log.Printf("cert type =%s", certType)
	w.WriteHeader(200)
	fmt.Fprintf(w, "Success!")
	return

}

func main() {
	flag.Parse()

	circularBuffer := logbuf.New()
	if circularBuffer == nil {
		panic("Cannot create circular buffer")
	}
	log.New(circularBuffer, "", log.LstdFlags)

	runtimeState, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		panic(err)
	}
	if *debug || true {
		log.Printf("After load verify")
	}

	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", prometheus.Handler())
	http.HandleFunc(SECRETINJECTOR_PATH, runtimeState.secretInjectorHandler)
	http.HandleFunc(CERTGEN_PATH, runtimeState.certGenHandler)
	http.HandleFunc(PUBLIC_PATH, runtimeState.publicPathHandler)
	http.HandleFunc(LOGIN_PATH, runtimeState.loginHandler)

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
	srv := &http.Server{
		Addr:         runtimeState.Config.Base.HttpAddress,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	err = srv.ListenAndServeTLS(
		runtimeState.Config.Base.TLSCertFilename,
		runtimeState.Config.Base.TLSKeyFilename)
	if err != nil {
		panic(err)
	}
}
