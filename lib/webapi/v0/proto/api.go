package proto

const LoginPath = "/api/v0/login"

const (
	AuthTypePassword    = "password"
	AuthTypeFederated   = "federated"
	AuthTypeU2F         = "U2F"
	AuthTypeSymantecVIP = "SymantecVIP"
)

type LoginResponse struct {
	Message         string   `json:"message"`
	CertAuthBackend []string `json:"auth_backend"`
}
