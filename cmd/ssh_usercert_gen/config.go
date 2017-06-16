package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type baseConfig struct {
	HttpAddress     string `yaml:"http_address"`
	TLSCertFilename string `yaml:"tls_cert_filename"`
	TLSKeyFilename  string `yaml:"tls_key_filename"`
	//UserAuth         string
	RequiredAuthForCert         string   `yaml:"required_auth_for_cert"`
	SSHCAFilename               string   `yaml:"ssh_ca_filename"`
	HtpasswdFilename            string   `yaml:"htpasswd_filename"`
	ClientCAFilename            string   `yaml:"client_ca_filename"`
	HostIdentity                string   `yaml:"host_identity"`
	KerberosRealm               string   `yaml:"kerberos_realm"`
	DataDirectory               string   `yaml:"data_directory"`
	AllowedAuthBackendsForCerts []string `yaml:"allowed_auth_backends_for_certs"`
}

type LdapConfig struct {
	Bind_Pattern     string
	LDAP_Target_URLs string
}

type Oauth2Config struct {
	Config       *oauth2.Config
	Enabled      bool   `yaml:"enabled"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	TokenUrl     string `yaml:"token_url"`
	AuthUrl      string `yaml:"auth_url"`
	UserinfoUrl  string `yaml:"userinfo_url"`
	Scopes       string `yaml:"scopes"`
	//Todo add allowed orgs...
}

type AppConfigFile struct {
	Base   baseConfig
	Ldap   LdapConfig
	Oauth2 Oauth2Config
}

const defaultRSAKeySize = 3072

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
	runtimeState.authCookie = make(map[string]authInfo)
	runtimeState.userProfile = make(map[string]userProfile)
	runtimeState.pendingOauth2 = make(map[string]pendingAuth2Request)

	//verify config
	if len(runtimeState.Config.Base.HostIdentity) > 0 {
		runtimeState.HostIdentity = runtimeState.Config.Base.HostIdentity
	} else {
		runtimeState.HostIdentity, err = getHostIdentity()
		if err != nil {
			return runtimeState, err
		}
	}
	// TODO: This assumes httpAddress is just the port..
	u2fAppID = "https://" + runtimeState.HostIdentity + runtimeState.Config.Base.HttpAddress
	u2fTrustedFacets = append(u2fTrustedFacets, u2fAppID)

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

	//create the oath2 config
	if runtimeState.Config.Oauth2.Enabled == true {
		log.Printf("oath2 is enabled")
		runtimeState.Config.Oauth2.Config = &oauth2.Config{
			ClientID:     runtimeState.Config.Oauth2.ClientID,
			ClientSecret: runtimeState.Config.Oauth2.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  runtimeState.Config.Oauth2.AuthUrl,
				TokenURL: runtimeState.Config.Oauth2.TokenUrl},
			RedirectURL: "https://" + runtimeState.HostIdentity + runtimeState.Config.Base.HttpAddress + redirectPath,
			Scopes:      strings.Split(runtimeState.Config.Oauth2.Scopes, " ")}
	}
	///
	err = runtimeState.LoadUserProfiles()
	if err != nil {
		log.Printf("Cannot load user Profile %s", err)
	}
	log.Printf("%+v", runtimeState.userProfile)

	// and we start the cleanup
	go runtimeState.performStateCleanup(secsBetweenCleanup)

	return runtimeState, nil
}

func generateArmoredEncryptedCAPritaveKey(passphrase []byte, filepath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	if err != nil {
		return err
	}

	encryptionType := "PGP SIGNATURE"
	armoredBuf := new(bytes.Buffer)
	armoredWriter, err := armor.Encode(armoredBuf, encryptionType, nil)
	if err != nil {
		return err
	}

	plaintextWriter, err := openpgp.SymmetricallyEncrypt(armoredWriter, passphrase, nil, nil)
	if err != nil {
		return err
	}

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(plaintextWriter, privateKeyPEM); err != nil {
		return err
	}
	plaintextWriter.Close()
	armoredWriter.Close()

	//os.Remove(filepath)
	return ioutil.WriteFile(filepath, armoredBuf.Bytes(), 0600)
}

func getPassphrase() ([]byte, error) {
	///matching := false
	for {
		fmt.Printf("Please enter your passphrase:\n")
		passphrase1, err := gopass.GetPasswd()
		if err != nil {
			return nil, err
		}
		fmt.Printf("Please re-enter your passphrase:\n")
		passphrase2, err := gopass.GetPasswd()
		if err != nil {
			return nil, err
		}
		if bytes.Equal(passphrase1, passphrase2) {
			return passphrase1, nil
		}
		fmt.Printf("Passphrases dont match, lets try again ")

	}
}

func getUserString(reader *bufio.Reader, displayValue, defaultValue string) (string, error) {
	fmt.Printf("%s[%s]:", displayValue, defaultValue)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(text) > 1 {
		return text, nil
	}
	return defaultValue, nil
}

func generateNewConfig(configFilename string) error {
	/*
		type baseConfig struct {
			HttpAddress     string `yaml:"http_address"`
			TLSCertFilename string `yaml:"tls_cert_filename"`
			TLSKeyFilename  string `yaml:"tls_key_filename"`
			//UserAuth         string
			RequiredAuthForCert         string   `yaml:"required_auth_for_cert"`
			SSHCAFilename               string   `yaml:"ssh_ca_filename"`
			HtpasswdFilename            string   `yaml:"htpasswd_filename"`
			ClientCAFilename            string   `yaml:"client_ca_filename"`
			HostIdentity                string   `yaml:"host_identity"`
			KerberosRealm               string   `yaml:"kerberos_realm"`
			DataDirectory               string   `yaml:"data_directory"`
			AllowedAuthBackendsForCerts []string `yaml:"allowed_auth_backends_for_certs"`
		}
	*/
	var config AppConfigFile
	//Get base dir
	reader := bufio.NewReader(os.Stdin)
	baseDir, err := getUserString(reader, "Default base Dir", "/tmp")
	/*
	 */
	if err != nil {
		return err
	}
	//fmt.Println(baseDir)
	config.Base.DataDirectory, err = getUserString(reader, "Data Directory", baseDir+"/var/lib/keymaster")
	if err != nil {
		return err
	}
	// TODO: Add check that directory exists.
	defaultHttpAddress := ":33443"
	config.Base.HttpAddress, err = getUserString(reader, "HttpAddress", defaultHttpAddress)
	// Todo check if valid

	//log.Printf("%+v", config)
	d, err := yaml.Marshal(&config)
	if err != nil {
		return err
	}
	fmt.Printf("--- m dump:\n%s\n\n", string(d))
	return nil
}
