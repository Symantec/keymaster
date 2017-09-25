package certnotifier

import (
	"bufio"
	"encoding/binary"
	"errors"
	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/keymaster/proto/certmon"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	bufferLength = 16
)

func newCertNotifier(logger log.DebugLogger) *CertNotifier {
	return &CertNotifier{
		logger:           logger,
		transmitChannels: make(map[chan<- transmitType]chan<- transmitType),
	}
}

func (n *CertNotifier) publish(certType uint32, certData []byte) {
	transmitData := transmitType{certType, certData}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	for ch := range n.transmitChannels {
		select {
		case ch <- transmitData:
		default:
		}
	}
}

func (n *CertNotifier) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != "CONNECT" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, bufRw, err := hijacker.Hijack()
	if err != nil {
		n.logger.Println("certmon hijacking ", req.RemoteAddr, ": ",
			err.Error())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	defer bufRw.Flush()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			n.logger.Println("error setting keepalive: ", err.Error())
			return
		}
		if err := tcpConn.SetKeepAlivePeriod(time.Minute * 5); err != nil {
			n.logger.Println("error setting keepalive period: ",
				err.Error())
			return
		}
	}
	_, err = io.WriteString(conn, "HTTP/1.0 "+certmon.ConnectString+"\n\n")
	if err != nil {
		n.logger.Println("error writing connect message: ", err.Error())
		return
	}
	n.logger.Println("certmon client connected")
	n.handleConnection(bufRw)
}

func (n *CertNotifier) handleConnection(rw *bufio.ReadWriter) {
	transmitChannel := make(chan transmitType, bufferLength)
	closeChannel := getCloseNotifier(rw)
	n.mutex.Lock()
	n.transmitChannels[transmitChannel] = transmitChannel
	n.mutex.Unlock()
	defer func() {
		n.mutex.Lock()
		delete(n.transmitChannels, transmitChannel)
		n.mutex.Unlock()
	}()
	for {
		select {
		case transmitData := <-transmitChannel:
			if err := transmit(rw, transmitData); err != nil {
				n.logger.Println(err)
				return
			}
		case err := <-closeChannel:
			if err == io.EOF {
				n.logger.Println("certmon client disconnected")
				return
			}
			n.logger.Println(err)
			return
		}
		if err := rw.Flush(); err != nil {
			n.logger.Println(err)
			return
		}
	}
}

func transmit(writer io.Writer, data transmitType) error {
	err := binary.Write(writer, binary.BigEndian, data.certType)
	if err != nil {
		return err
	}
	length := uint64(len(data.certData))
	if err := binary.Write(writer, binary.BigEndian, length); err != nil {
		return err
	}
	nWritten, err := writer.Write(data.certData)
	if err != nil {
		return err
	}
	if nWritten < int(length) {
		return errors.New("short write")
	}
	return nil
}

func getCloseNotifier(reader io.Reader) <-chan error {
	closeChannel := make(chan error)
	go func() {
		for {
			buf := make([]byte, 1)
			if _, err := reader.Read(buf); err != nil {
				closeChannel <- err
				return
			}
		}
	}()
	return closeChannel
}
