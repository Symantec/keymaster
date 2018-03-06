package monitord

import (
	"crypto/x509"
	"io"

	"github.com/Symantec/Dominator/lib/log"
	"golang.org/x/crypto/ssh"
)

type AuthInfo struct {
	AuthType string
	Username string
}

type Monitor struct {
	keymasterServerHostname string
	keymasterServerPortNum  uint
	closers                 map[string]chan<- struct{} // [addr]close notifier.
	// Transmit side channels (private).
	authChannel        chan<- AuthInfo
	sshRawCertChannel  chan<- []byte
	sshCertChannel     chan<- *ssh.Certificate
	webLoginChannel    chan<- string
	x509RawCertChannel chan<- []byte
	x509CertChannel    chan<- *x509.Certificate
	// Receive side channels (public).
	AuthChannel        <-chan AuthInfo
	SshRawCertChannel  <-chan []byte
	SshCertChannel     <-chan *ssh.Certificate
	WebLoginChannel    <-chan string
	X509RawCertChannel <-chan []byte
	X509CertChannel    <-chan *x509.Certificate
}

func New(keymasterServerHostname string, keymasterServerPortNum uint,
	logger log.Logger) (*Monitor, error) {
	return newMonitor(keymasterServerHostname, keymasterServerPortNum, logger)
}

func (m *Monitor) WriteHtml(writer io.Writer) {
	m.writeHtml(writer)
}
