package main

import (
	"flag"
	"text/template"

	"github.com/Symantec/Dominator/lib/log/serverlogger"
	"github.com/Symantec/keymaster/certmon/httpd"
	"github.com/Symantec/keymaster/certmon/monitord"
	"github.com/Symantec/keymaster/lib/constants"
	"github.com/Symantec/tricorder/go/tricorder"
)

var (
	configFile = flag.String("configFile",
		constants.DefaultKeymasterCertmonConfigFile, "Configuration file")
	portNum = flag.Uint("portNum", constants.DefaultCertmonPortNumber,
		"Port number to allocate and listed on for HTTP/RPC")
)

type configurationType struct {
	KeymasterServerHostname   string      `yaml:"keymaster_server_hostname"`
	KeymasterServerPortNum    uint        `yaml:"keymaster_server_port_num"`
	SshCertParametersCommand  certCommand `yaml:"ssh_cert_parameters_command"`
	SshCertRawCommand         string      `yaml:"ssh_cert_raw_command"`
	X509CertParametersCommand certCommand `yaml:"x509_cert_parameters_command"`
	X509CertRawCommand        string      `yaml:"x509_cert_raw_command"`
}

type certCommand struct {
	Command    string   `yaml:"command"`
	Parameters []string `yaml:"parameters"`
	templates  []*template.Template
}

func main() {
	flag.Parse()
	tricorder.RegisterFlags()
	logger := serverlogger.New("")
	configuration, err := loadConfig(*configFile)
	if err != nil {
		logger.Fatalf("Cannot load configuration: %s\n", err)
	}
	monitor, err := monitord.New(configuration.KeymasterServerHostname,
		configuration.KeymasterServerPortNum, logger)
	if err != nil {
		logger.Fatalf("Cannot start monitor: %s\n", err)
	}
	httpd.AddHtmlWriter(monitor)
	httpd.AddHtmlWriter(logger)
	if err = httpd.StartServer(*portNum, monitor, true); err != nil {
		logger.Fatalf("Unable to create http server: %s\n", err)
	}
	for {
		select {
		case cert := <-monitor.SshCertChannel:
			configuration.SshCertParametersCommand.processSshCert(cert)
		case cert := <-monitor.SshRawCertChannel:
			processRawCert(configuration.SshCertRawCommand, cert)
		case cert := <-monitor.X509CertChannel:
			configuration.X509CertParametersCommand.processX509Cert(cert)
		case cert := <-monitor.X509RawCertChannel:
			processRawCert(configuration.X509CertRawCommand, cert)
		}
	}
}
