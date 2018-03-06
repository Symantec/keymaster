package eventmon

const (
	ConnectString = "200 Connected to keymaster eventmon service"
	HttpPath      = "/eventmon/v0"

	AuthTypePassword    = "Password"
	AuthTypeSymantecVIP = "SymantecVIP"
	AuthTypeU2F         = "U2F"

	EventTypeSSHCert  = "SSHCert"
	EventTypeWebLogin = "WebLogin"
	EventTypeX509Cert = "X509Cert"
)

// Client sends no data. Server sends a sequence of events.

type EventV0 struct {
	Type string

	// Present for SSH and X509 certificate events.
	CertData []byte `json:",omitempty"`

	// Present for Web login events.
	AuthType string `json:",omitempty"`
	Username string `json:",omitempty"`
}
