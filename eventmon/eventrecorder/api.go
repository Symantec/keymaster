package eventrecorder

import (
	"crypto/x509"
	"time"

	"github.com/Symantec/Dominator/lib/log"
	"golang.org/x/crypto/ssh"
)

type Events struct {
	ComputeTime time.Duration
	Events      EventsMap
}

type EventsMap map[string][]EventType // Key: username.

type eventsListType struct {
	newest *eventType
	oldest *eventType
}

type EventType struct {
	CreateTime      uint64 // Seconds since Epoch.
	LifetimeSeconds uint32
	Ssh             bool
	X509            bool
}

type eventType struct {
	EventType
	newer *eventType
	older *eventType
}

type EventRecorder struct {
	RequestEventsChannel chan<- chan<- Events
	SshCertChannel       chan<- *ssh.Certificate
	X509CertChannel      chan<- *x509.Certificate
	filename             string
	logger               log.Logger
	eventsMap            map[string]*eventsListType // Key: username.
}

func New(filename string, logger log.Logger) (*EventRecorder, error) {
	return newEventRecorder(filename, logger)
}
