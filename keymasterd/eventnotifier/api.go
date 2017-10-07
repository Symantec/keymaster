package eventnotifier

import (
	"net/http"
	"sync"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/keymaster/proto/eventmon"
)

type EventNotifier struct {
	logger log.DebugLogger
	mutex  sync.Mutex
	// Protected by lock.
	transmitChannels map[chan<- eventmon.EventV0]chan<- eventmon.EventV0
}

func New(logger log.DebugLogger) *EventNotifier {
	return newEventNotifier(logger)
}

func (n *EventNotifier) PublishSSH(cert []byte) {
	n.publishCert("SSHCert", cert)
}

func (n *EventNotifier) PublishX509(cert []byte) {
	n.publishCert("X509Cert", cert)
}

func (n *EventNotifier) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	n.serveHTTP(w, req)
}
