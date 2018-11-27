package main

import (
	"net/http"
	"strings"
)

type logFilterType struct {
	handler    http.Handler
	publicLogs bool
}

func NewLogFilterHandler(handler http.Handler, disableFilter bool) http.Handler {
	return &logFilterType{
		handler:    handler,
		publicLogs: disableFilter,
	}
}

func getValidAdminRemoteUsername(w http.ResponseWriter,
	r *http.Request) (string, error) {
	if r.TLS != nil {
		logger.Debugf(4, "request is TLS %+v", r.TLS)
		if len(r.TLS.VerifiedChains) > 0 {
			logger.Debugf(4, "%+v", r.TLS.VerifiedChains[0][0].Subject)
			clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
			if clientName != "" {
				clientName = r.TLS.VerifiedChains[0][0].Subject.String()
			}
			return clientName, nil
		}
	}
	return "", nil
}

func (h *logFilterType) ServeHTTP(w http.ResponseWriter,
	req *http.Request) {
	if strings.HasPrefix(req.URL.Path, "/logs") {
		if !h.publicLogs {
			username, err := getValidAdminRemoteUsername(w, req)
			if err != nil {
				http.Error(w, "Check auth Failed", http.StatusInternalServerError)
				return
			}
			if username == "" {
				http.Error(w, "Invalid/Unknown Authentication", http.StatusUnauthorized)
				return
			}
		}
	}

	h.handler.ServeHTTP(w, req)
}
