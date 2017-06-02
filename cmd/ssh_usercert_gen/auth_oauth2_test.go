package main

import (
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"os"
	"testing"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

func init() {
	http.HandleFunc("/", handler)
	go http.ListenAndServe(":12345", nil)
}

var testOauth2Config = oauth2.Config{
	ClientID:     "foo",
	ClientSecret: "bar",
	Endpoint: oauth2.Endpoint{
		AuthURL:  "http://localhost:12345/auth",
		TokenURL: "http://localhost:12345/token"},
	RedirectURL: "https://example.com" + redirectPath,
	Scopes:      []string{"openidc", "email"},
}

func TestOauth2DoRedirectoToProviderHandlerSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.authCookie = make(map[string]authInfo)
	state.pendingOauth2 = make(map[string]pendingAuth2Request)
	state.Config.Oauth2.Config = &testOauth2Config

	req, err := http.NewRequest("GET", oauth2LoginBeginPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, state.oauth2DoRedirectoToProviderHandler, http.StatusFound)
	if err != nil {
		t.Fatal(err)
	}
	// Todo Check for the response contents
}

func TestOauth2RedirectPathHandlerSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up
	state.authCookie = make(map[string]authInfo)
	state.pendingOauth2 = make(map[string]pendingAuth2Request)
	state.Config.Oauth2.Config = &testOauth2Config

	//initially the request should fail for lack of preconditions
	req, err := http.NewRequest("GET", redirectPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	// request has no cookies
	_, err = checkRequestHandlerCode(req, state.oauth2RedirectPathHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}
}
