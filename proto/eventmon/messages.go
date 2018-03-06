package eventmon

const (
	ConnectString = "200 Connected to keymaster eventmon service"
	HttpPath      = "/eventmon/v0"

	AuthTypePassword    = "Password"
	AuthTypeSymantecVIP = "SymantecVIP"
	AuthTypeU2F         = "U2F"

	EventTypeAuth     = "Auth"
	EventTypeSSHCert  = "SSHCert"
	EventTypeWebLogin = "WebLogin"
	EventTypeX509Cert = "X509Cert"
)

// Client sends no data. Server sends a sequence of events.

type EventV0 struct {
	Type string

	// Present for SSH and X509 certificate events.
	CertData []byte `json:",omitempty"`

	AuthType string `json:",omitempty"` // Present for Auth events.
	Username string `json:",omitempty"` // Present for Auth and WebLogin events.
}
