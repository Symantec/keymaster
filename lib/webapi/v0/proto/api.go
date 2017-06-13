package proto

const LoginPath = "/api/v0/login"

const (
	AuthTypePassword = "password"
	AuthTypeU2F      = "U2F"
)

type LoginResponse struct {
	Message         string   `json:"message"`
	CertAuthBackend []string `json:"auth_backend"`
}
