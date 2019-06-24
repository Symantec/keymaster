package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/Dominator/lib/log/cmdlogger"
	"github.com/Symantec/Dominator/lib/net/rrdialer"
	"github.com/Symantec/keymaster/lib/client/config"
	libnet "github.com/Symantec/keymaster/lib/client/net"
	"github.com/Symantec/keymaster/lib/client/twofa"
	"github.com/Symantec/keymaster/lib/client/twofa/u2f"
	"github.com/Symantec/keymaster/lib/client/util"
)

const DefaultSSHKeysLocation = "/.ssh/"
const DefaultTLSKeysLocation = "/.ssl/"

const userAgentAppName = "keymaster"
const defaultVersionNumber = "No version provided"

var (
	// Must be a global variable in the data segment so that the build
	// process can inject the version number on the fly when building the
	// binary. Use only from the Usage() function.
	Version         = defaultVersionNumber
	userAgentString = userAgentAppName
)

var (
	configFilename   = flag.String("config", filepath.Join(getUserHomeDir(), ".keymaster", "client_config.yml"), "The filename of the configuration")
	rootCAFilename   = flag.String("rootCAFilename", "", "(optional) name for using non OS root CA to verify TLS connections")
	configHost       = flag.String("configHost", "", "Get a bootstrap config from this host")
	cliUsername      = flag.String("username", "", "username for keymaster")
	checkDevices     = flag.Bool("checkDevices", false, "CheckU2F devices in your system")
	cliFilePrefix    = flag.String("fileprefix", "", "Prefix for the output files")
	roundRobinDialer = flag.Bool("roundRobinDialer", false,
		"If true, use the smart round-robin dialer")

	FilePrefix = "keymaster"
	dialer     libnet.Dialer
)

func getUserHomeDir() (homeDir string) {
	homeDir = os.Getenv("HOME")
	if homeDir != "" {
		return homeDir
	}
	usr, err := user.Current()
	if err != nil {
		return homeDir
	}
	// TODO: verify on Windows... see: http://stackoverflow.com/questions/7922270/obtain-users-home-directory
	homeDir = usr.HomeDir
	return
}

func maybeGetRootCas(logger log.Logger) *x509.CertPool {
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
	return rootCAs
}

func getUserNameAndHomeDir(logger log.Logger) (userName, homeDir string) {
	usr, err := user.Current()
	if err != nil {
		logger.Printf("cannot get current user info")
		logger.Fatal(err)
	}
	userName = usr.Username

	if runtime.GOOS == "windows" {
		splitName := strings.Split(userName, "\\")
		if len(splitName) == 2 {
			userName = strings.ToLower(splitName[1])
		}
	}

	homeDir, err = util.GetUserHomeDir(usr)
	if err != nil {
		logger.Fatal(err)
	}
	return
}

func loadConfigFile(rootCAs *x509.CertPool, logger log.Logger) (
	configContents config.AppConfigFile) {
	configPath, _ := filepath.Split(*configFilename)

	err := os.MkdirAll(configPath, 0755)
	if err != nil {
		logger.Fatal(err)
	}

	if len(*configHost) > 1 {
		err = config.GetConfigFromHost(*configFilename, *configHost, rootCAs,
			dialer, logger)
		if err != nil {
			logger.Fatal(err)
		}
	} else if len(defaultConfigHost) > 1 { // if there is a configHost AND there is NO config file, create one
		if _, err := os.Stat(*configFilename); os.IsNotExist(err) {
			err = config.GetConfigFromHost(
				*configFilename, defaultConfigHost, rootCAs, dialer, logger)
			if err != nil {
				logger.Fatal(err)
			}
		}
	}

	configContents, err = config.LoadVerifyConfigFile(*configFilename)
	if err != nil {
		logger.Fatal(err)
	}
	return
}

func setupCerts(
	rootCAs *x509.CertPool,
	userName string,
	homeDir string,
	configContents config.AppConfigFile,
	logger log.DebugLogger) {
	// create dirs
	sshKeyPath := filepath.Join(homeDir, DefaultSSHKeysLocation, FilePrefix)
	sshConfigPath, _ := filepath.Split(sshKeyPath)
	err := os.MkdirAll(sshConfigPath, 0700)
	if err != nil {
		logger.Fatal(err)
	}
	tlsKeyPath := filepath.Join(homeDir, DefaultTLSKeysLocation, FilePrefix)
	tlsConfigPath, _ := filepath.Split(tlsKeyPath)
	err = os.MkdirAll(tlsConfigPath, 0700)
	if err != nil {
		logger.Fatal(err)
	}

	// get signer
	tempPrivateKeyPath := filepath.Join(homeDir, DefaultSSHKeysLocation, "keymaster-temp")
	signer, tempPublicKeyPath, err := util.GenKeyPair(
		tempPrivateKeyPath, userName+"@keymaster", logger)
	if err != nil {
		logger.Fatal(err)
	}
	defer os.Remove(tempPrivateKeyPath)
	defer os.Remove(tempPublicKeyPath)
	// Get user creds
	password, err := util.GetUserCreds(userName)
	if err != nil {
		logger.Fatal(err)
	}

	// Get the certs
	sshCert, x509Cert, kubernetesCert, err := twofa.GetCertFromTargetUrls(
		signer,
		userName,
		password,
		strings.Split(configContents.Base.Gen_Cert_URLS, ","),
		rootCAs,
		false,
		configContents.Base.AddGroups,
		dialer,
		userAgentString,
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
		cmd := exec.Command("ssh-add", "-d", sshKeyPath)
		cmd.Run()
	}

	//rename files to expected paths
	err = os.Rename(tempPrivateKeyPath, sshKeyPath)
	if err != nil {
		err := errors.New("Could not rename private Key")
		logger.Fatal(err)
	}

	err = os.Rename(tempPublicKeyPath, sshKeyPath+".pub")
	if err != nil {
		err := errors.New("Could not rename public Key")
		logger.Fatal(err)
	}
	// Now handle the key in the tls directory
	tlsPrivateKeyName := filepath.Join(homeDir, DefaultTLSKeysLocation, FilePrefix+".key")
	os.Remove(tlsPrivateKeyName)
	err = os.Symlink(sshKeyPath, tlsPrivateKeyName)
	if err != nil {
		// Try to copy instead (windows symlink does not work)
		from, err := os.Open(sshKeyPath)
		if err != nil {
			logger.Fatal(err)
		}
		defer from.Close()
		to, err := os.OpenFile(tlsPrivateKeyName, os.O_RDWR|os.O_CREATE, 0660)
		if err != nil {
			logger.Fatal(err)
		}
		defer to.Close()

		_, err = io.Copy(to, from)
		if err != nil {
			logger.Fatal(err)
		}
	}

	// now we write the cert file...
	sshCertPath := sshKeyPath + "-cert.pub"
	err = ioutil.WriteFile(sshCertPath, sshCert, 0644)
	if err != nil {
		err := errors.New("Could not write ssh cert")
		logger.Fatal(err)
	}
	x509CertPath := tlsKeyPath + ".cert"
	err = ioutil.WriteFile(x509CertPath, x509Cert, 0644)
	if err != nil {
		err := errors.New("Could not write ssh cert")
		logger.Fatal(err)
	}
	if kubernetesCert != nil {
		kubernetesCertPath := tlsKeyPath + "-kubernetes.cert"
		err = ioutil.WriteFile(kubernetesCertPath, kubernetesCert, 0644)
		if err != nil {
			err := errors.New("Could not write ssh cert")
			logger.Fatal(err)
		}
	}

	logger.Printf("Success")
	if _, ok := os.LookupEnv("SSH_AUTH_SOCK"); ok {
		// TODO(rgooch): Parse certificate to get actual lifetime.
		lifetime := fmt.Sprintf("%ds", uint64((*twofa.Duration).Seconds()))
		cmd := exec.Command("ssh-add", "-t", lifetime, sshKeyPath)
		cmd.Run()
	}
}

func computeUserAgent() {
	uaVersion := Version
	if Version == defaultVersionNumber {
		uaVersion = "0.0"
	}

	userAgentString = fmt.Sprintf("%s/%s (%s %s)", userAgentAppName, uaVersion, runtime.GOOS, runtime.GOARCH)
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
	rawDialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	if *roundRobinDialer {
		if rrDialer, err := rrdialer.New(rawDialer, "", logger); err != nil {
			logger.Fatalln(err)
		} else {
			defer rrDialer.WaitForBackgroundResults(time.Second)
			dialer = rrDialer
		}
	} else {
		dialer = rawDialer
	}

	if *checkDevices {
		u2f.CheckU2FDevices(logger)
		return
	}
	computeUserAgent()

	rootCAs := maybeGetRootCas(logger)
	userName, homeDir := getUserNameAndHomeDir(logger)
	config := loadConfigFile(rootCAs, logger)

	// Adjust user name
	if len(config.Base.Username) > 0 {
		userName = config.Base.Username
	}
	// command line always wins over pref or config
	if *cliUsername != "" {
		userName = *cliUsername
	}

	if len(config.Base.FilePrefix) > 0 {
		FilePrefix = config.Base.FilePrefix
	}
	if *cliFilePrefix != "" {
		FilePrefix = *cliFilePrefix
	}

	setupCerts(rootCAs, userName, homeDir, config, logger)
}
