package monitord

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/Dominator/lib/log/nulllogger"
	"github.com/Symantec/Dominator/lib/log/prefixlogger"
	"github.com/Symantec/Dominator/lib/log/teelogger"
	"github.com/Symantec/Dominator/lib/verstr"
	"github.com/Symantec/keymaster/eventmon/systeelogger"
	"github.com/Symantec/keymaster/proto/eventmon"
	"golang.org/x/crypto/ssh"
)

const (
	bufferLength = 16
)

var (
	ErrorKeymasterDaemonNotReady = errors.New("keymasterd not ready")
	One                          = systeelogger.New()
	Two                          = nulllogger.New() //remain for the future use
	Teelog                       teelogger.Logger
)

func newMonitor(keymasterServerHostname string, keymasterServerPortNum uint,
	logger log.Logger) (*Monitor, error) {
	authChannel := make(chan AuthInfo, bufferLength)
	serviceProviderLoginChannel := make(chan SPLoginInfo, bufferLength)
	sshRawCertChannel := make(chan []byte, bufferLength)
	sshCertChannel := make(chan *ssh.Certificate, bufferLength)
	webLoginChannel := make(chan string, bufferLength)
	x509RawCertChannel := make(chan []byte, bufferLength)
	x509CertChannel := make(chan *x509.Certificate, bufferLength)
	Teelog := teelogger.New(One, Two)
	defer One.Close()
	monitor := &Monitor{
		keymasterServerHostname: keymasterServerHostname,
		keymasterServerPortNum:  keymasterServerPortNum,
		closers:                 make(map[string]chan<- struct{}),
		// Transmit side channels (private).
		authChannel:                 authChannel,
		serviceProviderLoginChannel: serviceProviderLoginChannel,
		sshRawCertChannel:           sshRawCertChannel,
		sshCertChannel:              sshCertChannel,
		webLoginChannel:             webLoginChannel,
		x509RawCertChannel:          x509RawCertChannel,
		x509CertChannel:             x509CertChannel,
		// Receive side channels (public).
		AuthChannel:                 authChannel,
		ServiceProviderLoginChannel: serviceProviderLoginChannel,
		SshRawCertChannel:           sshRawCertChannel,
		SshCertChannel:              sshCertChannel,
		WebLoginChannel:             webLoginChannel,
		X509RawCertChannel:          x509RawCertChannel,
		X509CertChannel:             x509CertChannel,
		keymasterStatus:             make(map[string]error),
	}
	go monitor.monitorForever(logger, Teelog)
	return monitor, nil
}

func checkForEvent(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func (m *Monitor) monitorForever(logger log.Logger, Teelog log.Logger) {
	for ; ; time.Sleep(time.Minute * 2) {
		m.updateNotifierList(logger, Teelog)
	}
}

func (m *Monitor) updateNotifierList(logger log.Logger, Teelog log.Logger) {
	addrsToDelete := make(map[string]struct{})
	for addr := range m.closers {
		addrsToDelete[addr] = struct{}{}
	}
	addrsFound, err := net.LookupHost(m.keymasterServerHostname)
	if err != nil {
		logger.Println(err)
	}
	for _, addr := range addrsFound {
		if _, ok := m.closers[addr]; ok {
			delete(addrsToDelete, addr)
		} else {
			logger.Printf("New keymaster server: %s\n", addr)
			closeChannel := make(chan struct{}, 1)
			m.closers[addr] = closeChannel
			go m.startMonitoring(addr, closeChannel,
				prefixlogger.New(addr+": ", logger), Teelog)
		}
	}
	for addr := range addrsToDelete {
		logger.Printf("Deleting old keymaster server: %s\n", addr)
		m.closers[addr] <- struct{}{}
		delete(m.closers, addr)
		m.mutex.Lock()
		delete(m.keymasterStatus, addr)
		m.mutex.Unlock()
	}
}

func (m *Monitor) setKeymasterStatus(addr string, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.keymasterStatus[addr] = err
}

func (m *Monitor) startMonitoring(ip string, closeChannel <-chan struct{},
	logger log.Logger, Teelog log.Logger) {
	m.setKeymasterStatus(ip, errors.New("not yet probed"))
	addr := fmt.Sprintf("%s:%d", ip, m.keymasterServerPortNum)
	reportedNotReady := false
	for ; ; time.Sleep(time.Second) {
		if checkForEvent(closeChannel) {
			return
		}
		conn, err := m.dialAndConnect(addr)
		m.setKeymasterStatus(ip, err)
		if err != nil {
			if strings.Contains(err.Error(), "connection refused") {
				reportedNotReady = false
			} else if err == ErrorKeymasterDaemonNotReady {
				if !reportedNotReady {
					logger.Println(err)
					reportedNotReady = true
				}
			} else {
				logger.Println(err)
			}
			time.Sleep(time.Second * 4)
			continue
		}
		logger.Println("connected, starting monitoring")
		forget, err := m.monitor(conn, closeChannel, ip, logger, Teelog)
		if forget {
			return
		}
		if err != nil {
			logger.Println(err)
			conn.Close()
		}
	}
}

func (m *Monitor) dialAndConnect(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, time.Minute)
	if err != nil {
		return nil, err
	}
	if newConn, err := m.connect(conn); err != nil {
		conn.Close()
		return nil, err
	} else {
		return newConn, nil
	}
}

func (m *Monitor) connect(rawConn net.Conn) (net.Conn, error) {
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			return nil, err
		}
		if err := tcpConn.SetKeepAlivePeriod(time.Minute * 5); err != nil {
			return nil, err
		}
	}
	conn := tls.Client(rawConn,
		&tls.Config{ServerName: m.keymasterServerHostname})

	if err := conn.Handshake(); err != nil {
		return nil, err
	}
	io.WriteString(conn, "CONNECT "+eventmon.HttpPath+" HTTP/1.0\n\n")
	// Require successful HTTP response before enabling communications.
	resp, err := http.ReadResponse(bufio.NewReader(conn),
		&http.Request{Method: "CONNECT"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrorKeymasterDaemonNotReady
	}
	if resp.Status != eventmon.ConnectString {
		return nil, errors.New("unexpected HTTP response: " + resp.Status)
	}
	return conn, nil
}

func (m *Monitor) monitor(conn net.Conn, closeChannel <-chan struct{},
	ip string, logger log.Logger, Teelog log.Logger) (bool, error) {
	closedChannel := make(chan struct{}, 1)
	exitChannel := make(chan struct{})
	go func() {
		select {
		case <-closeChannel:
			closedChannel <- struct{}{}
			conn.Close()
		case <-exitChannel:
		}
	}()
	reader := bufio.NewReader(conn)
	for {
		receiveData, err := receiveV0(reader)
		if checkForEvent(closedChannel) {
			return true, nil
		}
		if err != nil {
			exitChannel <- struct{}{}
			if err == io.EOF {
				return false, errors.New("keymaster disconnected")
			}
			return false, err
		} else {
			m.notify(receiveData, ip, logger, Teelog)
		}
	}
}

func receiveV0(reader io.Reader) (eventmon.EventV0, error) {
	var event eventmon.EventV0
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&event); err != nil {
		return eventmon.EventV0{}, err
	}
	return event, nil
}

func (m *Monitor) writeHtml(writer io.Writer) {
	fmt.Fprintln(writer, "Keymasters:<br>")
	fmt.Fprintln(writer, `<table border="1">`)
	fmt.Fprintln(writer, "  <tr>")
	fmt.Fprintln(writer, "    <th>IP Addr</th>")
	fmt.Fprintln(writer, "    <th>Status</th>")
	fmt.Fprintln(writer, "  </tr>")
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	addrs := make([]string, 0, len(m.keymasterStatus))
	for addr := range m.keymasterStatus {
		addrs = append(addrs, addr)
	}
	verstr.Sort(addrs)
	for _, addr := range addrs {
		err := m.keymasterStatus[addr]
		var status string
		if err == nil {
			status = `<font color="green">ready</font>`
		} else if err == ErrorKeymasterDaemonNotReady {
			status = `<font color="red">sealed</font>`
		} else {
			status = err.Error()
		}
		fmt.Fprintln(writer, "  <tr>")
		fmt.Fprintf(writer, "    <td>%s</td>\n", addr)
		fmt.Fprintf(writer, "    <td>%s</td>\n", status)
		fmt.Fprintln(writer, "  </tr>")
	}
	fmt.Fprintln(writer, "</table>")
}

func (m *Monitor) notify(event eventmon.EventV0, ip string, logger log.Logger, Teelog log.Logger) {
	switch event.Type {
	case eventmon.EventTypeAuth:
		authType := event.AuthType
		var vipAuthType string
		if event.AuthType == eventmon.AuthTypeSymantecVIP {
			vipAuthType = event.VIPAuthType
			switch event.VIPAuthType {
			case eventmon.VIPAuthTypeOTP:
				authType += "/OTP"
			case eventmon.VIPAuthTypePush:
				authType += "/Push"
			default:
				authType += "/?"
			}
		}
		logger.Printf("User %s authentication: %s\n", authType, event.Username)
		Teelog.Print(fmt.Sprintf("%s: User %s authentication: %s", ip, authType, event.Username))
		select { // Non-blocking notification.
		case m.authChannel <- AuthInfo{
			AuthType:    event.AuthType,
			Username:    event.Username,
			VIPAuthType: vipAuthType,
		}:
		default:
		}
	case eventmon.EventTypeServiceProviderLogin:
		logger.Printf("User %s logged into service: %s\n",
			event.Username, event.ServiceProviderUrl)
		Teelog.Print(fmt.Sprintf("%s: User %s logged into service: %s", ip, event.Username, event.ServiceProviderUrl))
		select { // Non-blocking notification.
		case m.serviceProviderLoginChannel <- SPLoginInfo{
			URL:      event.ServiceProviderUrl,
			Username: event.Username,
		}:
		default:
		}
	case eventmon.EventTypeSSHCert:
		select { // Non-blocking notification.
		case m.sshRawCertChannel <- event.CertData:
		default:
		}
		if pubKey, err := ssh.ParsePublicKey(event.CertData); err != nil {
			logger.Println(err)
			Teelog.Print(fmt.Sprintf("%s: "+err.Error(), ip))
		} else if sshCert, ok := pubKey.(*ssh.Certificate); !ok {
			logger.Println("SSH public key is not a certificate")
			Teelog.Print(fmt.Sprintf("%s: SSH public key is not a certificate"))

		} else {
			switch len(sshCert.ValidPrincipals) {
			case 0:
				logger.Println(
					"Received SSH certificate with no valid principals")
				Teelog.Print(fmt.Sprintf("%s: Received SSH certificate with no valid principals", ip))
			case 1:
				logger.Printf("Received SSH certificate for: %s",
					sshCert.ValidPrincipals[0])
				Teelog.Print(fmt.Sprintf("%s: Received SSH certificate for: %s", ip, sshCert.ValidPrincipals[0]))
			default:
				logger.Printf("Received SSH certificate for: %s",
					sshCert.ValidPrincipals)
				Teelog.Print(fmt.Sprintf("%s: Received SSH certificate for: %s", ip, sshCert.ValidPrincipals))
			}
			select { // Non-blocking notification.
			case m.sshCertChannel <- sshCert:
			default:
			}
		}
	case eventmon.EventTypeWebLogin:
		logger.Printf("Web login for: %s\n", event.Username)
		select { // Non-blocking notification.
		case m.webLoginChannel <- event.Username:
		default:
		}
	case eventmon.EventTypeX509Cert:
		select { // Non-blocking notification.
		case m.x509RawCertChannel <- event.CertData:
		default:
		}
		if x509Cert, err := x509.ParseCertificate(event.CertData); err != nil {
			logger.Println(err)
		} else {
			logger.Printf("Received X509 certificate for: %s\n",
				x509Cert.Subject.CommonName)
			Teelog.Print(fmt.Sprintf("%s: Received X509 certificate for: %s", ip, x509Cert.Subject.CommonName))
			select { // Non-blocking notification.
			case m.x509CertChannel <- x509Cert:
			default:
			}
		}
	default:
		logger.Printf("Invalid event type: %s\n", event.Type)
		Teelog.Print(fmt.Sprintf("%s: Invalid event type: %s", ip, event.Type))
	}
}
