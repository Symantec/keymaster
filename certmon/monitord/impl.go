package monitord

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/Dominator/lib/log/prefixlogger"
	"github.com/Symantec/keymaster/proto/certmon"
	"golang.org/x/crypto/ssh"
)

const bufferLength = 16

type receiveType struct {
	certType uint32
	certData []byte
}

func newMonitor(keymasterServerHostname string, keymasterServerPortNum uint,
	logger log.Logger) (*Monitor, error) {
	sshRawCertChannel := make(chan []byte, bufferLength)
	sshCertChannel := make(chan *ssh.Certificate, bufferLength)
	x509RawCertChannel := make(chan []byte, bufferLength)
	x509CertChannel := make(chan *x509.Certificate, bufferLength)
	monitor := &Monitor{
		keymasterServerHostname: keymasterServerHostname,
		keymasterServerPortNum:  keymasterServerPortNum,
		closers:                 make(map[string]chan<- struct{}),
		// Transmit side channels (private).
		sshRawCertChannel:  sshRawCertChannel,
		sshCertChannel:     sshCertChannel,
		x509RawCertChannel: x509RawCertChannel,
		x509CertChannel:    x509CertChannel,
		// Receive side channels (public).
		SshRawCertChannel:  sshRawCertChannel,
		SshCertChannel:     sshCertChannel,
		X509RawCertChannel: x509RawCertChannel,
		X509CertChannel:    x509CertChannel,
	}
	go monitor.monitorForever(logger)
	return monitor, nil
}

func (m *Monitor) monitorForever(logger log.Logger) {
	for ; ; time.Sleep(time.Minute * 5) {
		m.updateNotifierList(logger)
	}
}

func (m *Monitor) updateNotifierList(logger log.Logger) {
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
				prefixlogger.New(addr+": ", logger))
		}
	}
	for addr := range addrsToDelete {
		logger.Printf("Deleting old keymaster server: %s\n", addr)
		m.closers[addr] <- struct{}{}
		delete(m.closers, addr)
	}
}

func (m *Monitor) startMonitoring(ip string, closeChannel <-chan struct{},
	logger log.Logger) {
	addr := fmt.Sprintf("%s:%d", ip, m.keymasterServerPortNum)
	for ; ; time.Sleep(time.Second) {
		conn, err := m.dialAndConnect(addr)
		if err != nil {
			if !strings.Contains(err.Error(), "connection refused") {
				logger.Println(err)
			}
			time.Sleep(time.Second * 4)
			continue
		}
		logger.Println("connected, starting monitoring")
		if err := m.monitor(conn, closeChannel, logger); err != nil {
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
	io.WriteString(conn, "CONNECT "+certmon.HttpPath+" HTTP/1.0\n\n")
	// Require successful HTTP response before enabling communications.
	resp, err := http.ReadResponse(bufio.NewReader(conn),
		&http.Request{Method: "CONNECT"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("keymaster not ready")
	}
	if resp.Status != certmon.ConnectString {
		return nil, errors.New("unexpected HTTP response: " + resp.Status)
	}
	return conn, nil
}

func (m *Monitor) monitor(conn net.Conn, closeChannel <-chan struct{},
	logger log.Logger) error {
	closed := false
	exitChannel := make(chan struct{})
	go func() {
		for {
			select {
			case <-closeChannel:
				closed = true
				conn.Close()
			case <-exitChannel:
				return
			}
		}
	}()
	reader := bufio.NewReader(conn)
	for {
		if receiveData, err := receive(reader); err != nil {
			if closed {
				return nil
			}
			exitChannel <- struct{}{}
			if err == io.EOF {
				return errors.New("keymaster disconnected")
			}
			return err
		} else {
			m.notify(receiveData, logger)
		}
	}
	return nil
}

func receive(reader io.Reader) (receiveType, error) {
	var rd receiveType
	if err := binary.Read(reader, binary.BigEndian, &rd.certType); err != nil {
		return rd, err
	}
	var certLength uint64
	if err := binary.Read(reader, binary.BigEndian, &certLength); err != nil {
		return rd, err
	}
	rd.certData = make([]byte, certLength)
	if nRead, err := reader.Read(rd.certData); err != nil {
		return rd, err
	} else {
		if nRead != int(certLength) {
			return rd, errors.New("short read")
		}
	}
	return rd, nil
}

func (m *Monitor) writeHtml(writer io.Writer) {
}

func (m *Monitor) notify(data receiveType, logger log.Logger) {
	switch data.certType {
	case certmon.CertTypeSSH:
		logger.Println("Received SSH certificate")
		select { // Non-blocking notification.
		case m.sshRawCertChannel <- data.certData:
		default:
		}
		// if sshCert, err := ssh.ParseCertificate(data.certData); err != nil {
		// 	logger.Println(err)
		// } else {
		// 	select { // Non-blocking notification.
		// 	case m.sshCertChannel <- sshCert:
		// 	default:
		// 	}
		// }
	case certmon.CertTypeX509:
		select { // Non-blocking notification.
		case m.x509RawCertChannel <- data.certData:
		default:
		}
		if x509Cert, err := x509.ParseCertificate(data.certData); err != nil {
			logger.Println(err)
		} else {
			logger.Printf("Received X509 certificate for: %s\n",
				x509Cert.Subject.CommonName)
			select { // Non-blocking notification.
			case m.x509CertChannel <- x509Cert:
			default:
			}
		}
	default:
		logger.Printf("Invalid cert type: %d\n", data.certType)
	}
}
