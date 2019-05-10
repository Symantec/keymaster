package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"os"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/keymaster/lib/client/net"
	"github.com/Symantec/keymaster/lib/client/util"
	"gopkg.in/yaml.v2"
)

func loadVerifyConfigFile(configFilename string) (AppConfigFile, error) {
	var config AppConfigFile
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("No config file: please re-run with -configHost")
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

	if len(config.Base.Gen_Cert_URLS) < 1 {
		err = errors.New("Invalid Config file... no place get the certs")
		return config, err
	}
	// TODO: ensure all enpoints are https urls

	return config, nil
}

const hostConfigPath = "/public/clientConfig"

func getConfigFromHost(
	configFilename string,
	hostname string,
	rootCAs *x509.CertPool,
	dialer net.Dialer,
	logger log.Logger) error {
	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}
	client, err := util.GetHttpClient(tlsConfig, dialer)
	if err != nil {
		return err
	}
	configUrl := "https://" + hostname + hostConfigPath
	/*
		        req, err := http.NewRequest("GET", configUrl, nil)
				        if err != nil {
								            return err
											        }
	*/
	resp, err := client.Get(configUrl)
	if err != nil {
		logger.Printf("got error from req")
		logger.Println(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logger.Printf("got error from getconfig call %s", resp)
		return err
	}
	configData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configFilename, configData, 0644)
}
