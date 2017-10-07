package eventmon

const (
	ConnectString = "200 Connected to keymaster eventmon service"
	HttpPath      = "/eventmon/v0"

	EventTypeSSHCert  = "SSHCert"
	EventTypeX509Cert = "X509Cert"
)

// Client sends no data. Server sends a sequence of events.

type EventV0 struct {
	Type     string
	CertData []byte `json:",omitempty"`
}
