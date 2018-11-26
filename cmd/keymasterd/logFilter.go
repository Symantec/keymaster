package main

import (
	"net/http"
	"strings"
)

type logFilterType struct {
	handler    http.Handler
	publicLogs bool
}

func NewLogFilerHandler(handler http.Handler, disableFilter bool) http.Handler {
	return &logFilterType{
		handler:    handler,
		publicLogs: disableFilter,
	}
}

func (h *logFilterType) ServeHTTP(w http.ResponseWriter,
	req *http.Request) {

	if !h.publicLogs && strings.HasPrefix(req.URL.Path, "/logs") {
		http.NotFound(w, req)
		return
	}

	h.handler.ServeHTTP(w, req)
}
