package certmon

const (
	CertTypeSSH  = 0
	CertTypeX509 = 1
)

// Format of certificate notifications (server -> client):
// certType:   32 bit uint (big-endian)
// certLength: 64 bit uint (big-endian)
// certData:   sequence of bytes

// Client sends no data.
