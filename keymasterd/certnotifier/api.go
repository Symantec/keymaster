package certnotifier

import (
	"net/http"
	"sync"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/keymaster/proto/certmon"
)

type CertNotifier struct {
	logger log.DebugLogger
	mutex  sync.Mutex
	// Protected by lock.
	transmitChannels map[chan<- transmitType]chan<- transmitType
}

type transmitType struct {
	certType uint32
	certData []byte
}

func New(logger log.DebugLogger) *CertNotifier {
	return newCertNotifier(logger)
}

func (n *CertNotifier) PublishSSH(cert []byte) {
	n.publish(certmon.CertTypeSSH, cert)
}

func (n *CertNotifier) PublishX509(cert []byte) {
	n.publish(certmon.CertTypeX509, cert)
}

func (n *CertNotifier) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	n.serveHTTP(w, req)
}
