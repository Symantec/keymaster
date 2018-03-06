package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/Dominator/lib/log/cmdlogger"
	"github.com/Symantec/keymaster/lib/client/config"
	"github.com/Symantec/keymaster/lib/client/twofa"
	"github.com/Symantec/keymaster/lib/client/twofa/u2f"
	"github.com/Symantec/keymaster/lib/client/util"
)

const DefaultSSHKeysLocation = "/.ssh/"
const DefaultTLSKeysLocation = "/.ssl/"

const FilePrefix = "keymaster"

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
	checkDevices   = flag.Bool("checkDevices", false, "CheckU2F devices in your system")
)

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

	configContents, err = config.LoadVerifyConfigFile(*configFilename)
	if err != nil {
		logger.Fatal(err)
	}
	return
}

func setupCerts(
	rootCAs *x509.CertPool,
	userName,
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
		u2f.CheckU2FDevices(logger)
		return
	}

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
	setupCerts(rootCAs, userName, homeDir, config, logger)
}
