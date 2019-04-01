package config

import (
	"crypto/x509"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/keymaster/lib/client/net"
)

type BaseConfig struct {
	Gen_Cert_URLS string `yaml:"gen_cert_urls"`
	Username      string `yaml:"username"`
	FilePrefix    string `yaml:"file_prefix"`
	AddGroups     bool   `yaml:"add_groups"`
}

// AppConfigFile represents a keymaster client configuration file
type AppConfigFile struct {
	Base BaseConfig
}

// LoadVerifyConfigFile reads, verifies, and returns the contents of
// a keymaster configuration file. LoadVerifyConfigFile returns an error if the
// configuration file is invalid.
func LoadVerifyConfigFile(configFilename string) (AppConfigFile, error) {
	return loadVerifyConfigFile(configFilename)
}

// GetConfigFromHost grabs a default config file from a given host and stores
// it in the local file system.
func GetConfigFromHost(
	configFilename string,
	hostname string,
	rootCAs *x509.CertPool,
	dialer net.Dialer,
	logger log.Logger) error {
	return getConfigFromHost(configFilename, hostname, rootCAs, dialer, logger)
}
