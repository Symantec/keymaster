package httpd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Symantec/keymaster/eventmon/eventrecorder"
	"github.com/Symantec/keymaster/eventmon/monitord"
)

type HtmlWriter interface {
	WriteHtml(writer io.Writer)
}

var htmlWriters []HtmlWriter

type state struct {
	eventRecorder *eventrecorder.EventRecorder
	monitor       *monitord.Monitor
}

func StartServer(portNum uint, eventRecorder *eventrecorder.EventRecorder,
	monitor *monitord.Monitor, daemon bool) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portNum))
	if err != nil {
		return err
	}
	serviceSrv := &http.Server{
		Handler:      http.DefaultServeMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	err = AttachHandlersToHttpServerMux(http.DefaultServeMux, eventRecorder, monitor)
	if err != nil {
		return err
	}
	if daemon {
		go serviceSrv.Serve(listener)
		return nil
	} else {
		return serviceSrv.Serve(listener)
	}
}

func AttachHandlersToHttpServerMux(serviceMux *http.ServeMux, eventRecorder *eventrecorder.EventRecorder,
	monitor *monitord.Monitor) error {
	myState := state{eventRecorder, monitor}
	serviceMux.HandleFunc("/", myState.statusHandler)
	serviceMux.HandleFunc("/showActivity", myState.showActivityHandler)
	return nil
}

func AddHtmlWriter(htmlWriter HtmlWriter) {
	htmlWriters = append(htmlWriters, htmlWriter)
}
