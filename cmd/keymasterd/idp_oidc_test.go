package main

import (
	//"encoding/json"
	//"fmt"
	stdlog "log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Symantec/Dominator/lib/log/debuglogger"
	"gopkg.in/square/go-jose.v2/jwt"
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
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}

	//url := idpOpenIDCAuthorizationPath
	req, err := http.NewRequest("GET", idpOpenIDCAuthorizationPath, nil)

	//First we do a simple request.. no auth should fail for now.. after build out it
	// should be a redirect to the login page
	_, err = checkRequestHandlerCode(req, state.idpOpenIDCAuthorizationHandler, http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	// now we add a cookie for auth
	cookieVal := "supersecret"
	state.authCookie[cookieVal] = authInfo{
		Username:  "username",
		ExpiresAt: time.Now().Add(120 * time.Second),
		AuthType:  AuthTypePassword}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	req.AddCookie(&authCookie)
	// and we retry with no params... it should fail again
	_, err = checkRequestHandlerCode(req, state.idpOpenIDCAuthorizationHandler, http.StatusBadRequest)
	if err != nil {
		t.Fatal(err)
	}
	// add the required params
	form := url.Values{}
	form.Add("scope", "openid")
	form.Add("response_type", "code")
	form.Add("client_id", "valid_client_id")
	form.Add("redirect_uri", "https://localhost:12345")
	form.Add("state", "this is my state")

	postReq, err := http.NewRequest("POST", idpOpenIDCAuthorizationPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	postReq.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	postReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	postReq.AddCookie(&authCookie)

	rr, err := checkRequestHandlerCode(postReq, state.idpOpenIDCAuthorizationHandler, http.StatusFound)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", rr)
	locationText := rr.Header().Get("Location")
	t.Logf("location=%s", locationText)
	location, err := url.Parse(locationText)
	if err != nil {
		t.Fatal(err)
	}
	rCode := location.Query().Get("code")
	t.Logf("rCode=%s", rCode)
	tok, err := jwt.ParseSigned(rCode)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tok=%+v", tok)
	//out := jwt.Claims{}
	out := keymasterdCodeToken{}
	if err := tok.Claims(state.Signer.Public(), &out); err != nil {
		t.Fatal(err)
	}
	t.Logf("out=%+v", out)

}
