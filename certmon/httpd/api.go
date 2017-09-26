package httpd

import (
	"fmt"
	"github.com/Symantec/keymaster/certmon/monitord"
	"io"
	"net"
	"net/http"
)

type HtmlWriter interface {
	WriteHtml(writer io.Writer)
}

var htmlWriters []HtmlWriter

type state struct {
	monitor *monitord.Monitor
}

func StartServer(portNum uint, monitor *monitord.Monitor, daemon bool) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portNum))
	if err != nil {
		return err
	}
	myState := state{monitor}
	http.HandleFunc("/", myState.statusHandler)
	if daemon {
		go http.Serve(listener, nil)
	} else {
		http.Serve(listener, nil)
	}
	return nil
}

func AddHtmlWriter(htmlWriter HtmlWriter) {
	htmlWriters = append(htmlWriters, htmlWriter)
}
