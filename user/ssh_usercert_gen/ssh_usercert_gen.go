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
		//log.Fatal(err)
		return "", err
	}
	log.Printf("Pub key: %s\n", out.String())
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
	//log.Printf("%+v", c)
	certBytes := c.Marshal()
	encoded := base64.StdEncoding.EncodeToString(certBytes)
	fileComment := "/tmp/" + username + "-cert.pub"
	return "ssh-rsa-cert-v01@openssh.com " + encoded + " " + fileComment, nil

	//return "", nil
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
	//log.Printf("After all parsing and loading")
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
		//panic(err)
		err = errors.New("cannot read " + description + "file")
		return err
	}
	return nil
}

func loadVerifyConfigFile(configFilename string) (AppConfigFile, error) {
	var config AppConfigFile
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		//log.Printf("Missing config file\n")
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
	//connectionAttemptCounter.WithLabelValues(server).Add(1)
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

func writeUnauthorizedResponse(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="User Credentials"`)
	w.WriteHeader(401)
	w.Write([]byte("401 Unauthorized\n"))
}

func writeForbiddenResponse(w http.ResponseWriter) {
	w.WriteHeader(403)
	w.Write([]byte("403 Forbidden\n"))
}

// Inspired by http://stackoverflow.com/questions/21936332/idiomatic-way-of-requiring-http-basic-auth-in-go
func checkAuth(w http.ResponseWriter, r *http.Request, config AppConfigFile) (string, error) {
	//For now just check http basic
	user, pass, ok := r.BasicAuth()
	if !ok {
		writeUnauthorizedResponse(w)
		err := errors.New("check_Auth, Invalid or no auth header")
		return "", err
	}
	valid, err := checkUserPassword(user, pass, config)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("400 Internal Error\n"))
		return "", err
	}
	if !valid {
		writeUnauthorizedResponse(w)
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
		writeForbiddenResponse(w)
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
		}
	case "POST":
		if *debug {
			log.Printf("Got client POST connection")
		}
		err = r.ParseMultipartForm(1e7)
		if err != nil {
			log.Println(err)
			w.WriteHeader(400)
			w.Write([]byte("400 Error parsing Form\n"))
			return
		}

		file, _, err := r.FormFile("pubkeyfile")
		if err != nil {
			log.Println(err)
			w.WriteHeader(400)
			w.Write([]byte("400 Missing file\n"))
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
			w.WriteHeader(500)
			w.Write([]byte("500 MatchString internal error\n"))
			return
		}
		if !validKey {
			log.Printf("invalid file, bad re")
			w.WriteHeader(400)
			w.Write([]byte("400 Bad Key File"))
			return

		}

		cert, err = signUserPubKey(targetUser, userPubKey, config.Base.SSH_CA_Filename)
		if err != nil {
			log.Printf("signUserPubkey Err")
			http.NotFound(w, r)
		}

	default:
		w.WriteHeader(405)
		w.Write([]byte("405 Method Not Allowed\n"))
		return

	}
	w.Header().Set("Content-Disposition", `attachment; filename="id_rsa-cert.pub"`)
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", cert)
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
	//http.HandleFunc(CERTGEN_PATH, certGenHandler)
	http.HandleFunc(CERTGEN_PATH, config.certGenHandler)
	err = http.ListenAndServeTLS(
		config.Base.Http_Address,
		config.Base.TLS_Cert_Filename,
		config.Base.TLS_Key_Filename,
		nil)
	if err != nil {
		panic(err)
	}
}
