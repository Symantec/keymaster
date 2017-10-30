package main

import (
	//"encoding/json"
	//"fmt"
	stdlog "log"
	"net/http"
	"os"
	"testing"
	//"time"

	"github.com/Symantec/Dominator/lib/log/debuglogger"
	//"golang.org/x/net/context"
	//"golang.org/x/oauth2"
)

func init() {
	//logger = stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	logger = debuglogger.New(slogger)
	/*
		http.HandleFunc("/userinfo", userinfoHandler)
		http.HandleFunc("/token", tokenHandler)
		http.HandleFunc("/", handler)
		logger.Printf("about to start server")
		go http.ListenAndServe(":12345", nil)
		time.Sleep(20 * time.Millisecond)
		_, err := http.Get("http://localhost:12345")
		if err != nil {
			logger.Fatal(err)
		}
	*/
}

func TestIDPOpenIDCMetadataHandler(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.authCookie = make(map[string]authInfo)
	state.pendingOauth2 = make(map[string]pendingAuth2Request)

	url := idpOpenIDCConfigurationDocumentPath
	req, err := http.NewRequest("GET", url, nil)
	_, err = checkRequestHandlerCode(req, state.idpOpenIDCDiscoveryHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}

func TestIDPOpenIDCJWKSHandler(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.authCookie = make(map[string]authInfo)
	state.pendingOauth2 = make(map[string]pendingAuth2Request)

	url := idpOpenIDCJWKSPath
	req, err := http.NewRequest("GET", url, nil)
	_, err = checkRequestHandlerCode(req, state.idpOpenIDCJWKSHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}

func TestIDPOpenIDCAuthorizationHandlerSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.authCookie = make(map[string]authInfo)
	state.pendingOauth2 = make(map[string]pendingAuth2Request)

	url := idpOpenIDCAuthorizationPath
	req, err := http.NewRequest("GET", url, nil)

	//First we do a simple request.. no auth should fail for now.. after build out it
	// should be a redirect to the login page
	_, err = checkRequestHandlerCode(req, state.idpOpenIDCAuthorizationHandler, http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	// add fa
}
