package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ssh"
	"gopkg.in/ldap.v2"
	"gopkg.in/yaml.v2"
	//"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	//"strconv"
	"strings"
	//"sync"
	"time"
)

// describes the network config and the mechanism for user auth.
// While the contents of the certificaes are public, we want to
// restrict generation to authenticated users
type baseConfig struct {
	Http_Address      string
	TLS_Cert_Filename string
	TLS_Key_Filename  string
	UserAuth          string
	SSH_CA_Filename   string
}

type LdapConfig struct {
	Bind_Pattern     string
	LDAP_Target_URLs string
}

type AppConfigFile struct {
	Base baseConfig
	Ldap LdapConfig
}

var (
	configFilename = flag.String("config", "config.yml", "The filename of the configuration")
	debug          = flag.Bool("debug", false, "Enable debug messages to console")
)

func getUserPubKey(username string) (string, error) {
	cmd := exec.Command("/usr/bin/sss_ssh_authorizedkeys", username)
	cmd.Stdin = strings.NewReader("some input")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	if *debug {
		log.Printf("Pub key(%s): %s\n", username, out.String())
	}
	return out.String(), nil
}

func signUserPubKey(username string, userPubKey string, users_ca_filename string) (string, error) {
	hostIdentity, err := getHostIdentity()
	if err != nil {
		log.Println(err)
		return "", err
	}
	return signUserPubKeyHostIdent(username, userPubKey, users_ca_filename, hostIdentity)
}

func goCertToFileString(c ssh.Certificate, username string) (string, error) {
	certBytes := c.Marshal()
	encoded := base64.StdEncoding.EncodeToString(certBytes)
	fileComment := "/tmp/" + username + "-cert.pub"
	return "ssh-rsa-cert-v01@openssh.com " + encoded + " " + fileComment, nil
}

// gen_user_cert a username and key, returns a short lived cert for that user
func signUserPubKeyHostIdent(username string, userPubKey string, users_ca_filename string, host_identity string) (string, error) {
	const numValidHours = 24

	// load private key and make signer
	buffer, err := ioutil.ReadFile(users_ca_filename)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		log.Printf("Cannot parse Priave Key file")
		return "", err
	}
	userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(userPubKey))
	if err != nil {
		log.Printf("Cannot Parse User Public Key")
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
		log.Printf("Cannot sign cert")
		return "", err
	}
	certString, err := goCertToFileString(cert, username)
	if err != nil {
		log.Printf("Cannot convert cert to string")
		return "", err
	}
	return certString, nil
}

func getHostIdentity() (string, error) {
	return os.Hostname()
}

func genUserCert(userName string, users_ca_filename string) (string, error) {

	userPubKey, err := getUserPubKey(userName)
	if err != nil {
		log.Println(err)
		return "", err
	}

	cert, err := signUserPubKey(userName, userPubKey, users_ca_filename)
	if err != nil {
		log.Fatal(err)
	}
	return cert, err
}

func exitsAndCanRead(fileName string, description string) error {
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		err = errors.New("mising " + description + " file")
		return err
	}
	_, err := ioutil.ReadFile(fileName)
	if err != nil {
		err = errors.New("cannot read " + description + "file")
		return err
	}
	return nil
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

	//verify config
	err = exitsAndCanRead(config.Base.SSH_CA_Filename, "ssh CA File")
	if err != nil {
		return config, err
	}
	err = exitsAndCanRead(config.Base.TLS_Cert_Filename, "http cert file")
	if err != nil {
		return config, err
	}
	err = exitsAndCanRead(config.Base.TLS_Key_Filename, "http key file")
	if err != nil {
		return config, err
	}

	return config, nil
}

func checkLDAPUserPassword(u url.URL, bindDN string, bindPassword string, timeoutSecs uint) (bool, error) {
	if u.Scheme != "ldaps" {
		err := errors.New("Invalid ldap scheme (we only support ldaps")
		return false, err
	}
	//hostnamePort := server + ":636"
	serverPort := strings.Split(u.Host, ":")
	port := "636"
	if len(serverPort) == 2 {
		port = serverPort[1]
	}
	server := serverPort[0]
	hostnamePort := server + ":" + port
	if *debug {
		log.Println("about to connect to:" + hostnamePort)
	}

	timeout := time.Duration(time.Duration(timeoutSecs) * time.Second)
	start := time.Now()
	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", hostnamePort, &tls.Config{ServerName: server})
	if err != nil {
		errorTime := time.Since(start).Seconds() * 1000
		log.Printf("connction failure for:%s (%s)(time(ms)=%v)", server, err.Error(), errorTime)
		return false, err
	}

	// we dont close the tls connection directly  close defer to the new ldap connection
	conn := ldap.NewConn(tlsConn, true)
	defer conn.Close()

	connectionTime := time.Since(start).Seconds() * 1000
	if *debug {
		log.Printf("connectionDelay = %v connecting to: %v:", connectionTime, hostnamePort)
	}

	conn.SetTimeout(timeout)
	conn.Start()
	err = conn.Bind(bindDN, bindPassword)
	if err != nil {
		log.Printf("Bind failure for server:%s bindDN:'%s' (%s)", server, bindDN, err.Error())
		return false, err
	}
	return true, nil

}

func parseLDAPURL(ldapUrl string) (*url.URL, error) {
	u, err := url.Parse(ldapUrl)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ldaps" {
		err := errors.New("Invalid ldap scheme (we only support ldaps")
		return nil, err
	}
	//extract port if any... and if NIL then set it to 636
	return u, nil
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
		u, err := parseLDAPURL(ldapUrl)
		if err != nil {
			log.Printf("Failed to parse %s", ldapUrl)
			continue
		}
		vaild, err := checkLDAPUserPassword(*u, bindDN, password, timeoutSecs)
		if err != nil {
			//log.Printf("Failed to parse %s", ldapUrl)
			continue
		}
		// the ldap exchange was successful (user might be invaid)
		return vaild, nil

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

func (config AppConfigFile) certGenHandler(w http.ResponseWriter, r *http.Request) {
	// TODO(camilo_viecco1): reorder checks so that simple checks are done before checking user creds

	authUser, err := checkAuth(w, r, config)
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

	var cert string
	switch r.Method {
	case "GET":
		cert, err = genUserCert(targetUser, config.Base.SSH_CA_Filename)
		if err != nil {
			http.NotFound(w, r)
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

		cert, err = signUserPubKey(targetUser, userPubKey, config.Base.SSH_CA_Filename)
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
	log.Printf("Generated Certifcate for %s", targetUser)
}

func main() {
	flag.Parse()

	config, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		panic(err)
	}
	cert, err := genUserCert("camilo_viecco1", config.Base.SSH_CA_Filename)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("cert='%s'", cert)

	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", prometheus.Handler())
	http.HandleFunc(CERTGEN_PATH, config.certGenHandler)

	cfg := &tls.Config{
		ClientAuth:               tls.RequestClientCert,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	srv := &http.Server{
		Addr:         config.Base.Http_Address,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	err = srv.ListenAndServeTLS(
		config.Base.TLS_Cert_Filename,
		config.Base.TLS_Key_Filename)
	if err != nil {
		panic(err)
	}
}
