package okta

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"
)

var authnURL string

func authnHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var loginData loginDataType
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&loginData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if loginData.Username != "a-user" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch loginData.Password {
	case "good-password":
		writeStatus(w, "SUCCESS")
		return
	case "needs-2FA":
		writeStatus(w, "MFA_REQUIRED")
		return
	case "password-expired":
		writeStatus(w, "PASSWORD_EXPIRED")
		return
	default:
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func setupServer() {
	if authnURL != "" {
		return
	}
	if listener, err := net.Listen("tcp", ""); err != nil {
		panic(err)
	} else {
		addr := listener.Addr().String()
		authnURL = "http://" + addr + authPath
		serveMux := http.NewServeMux()
		serveMux.HandleFunc(authPath, authnHandler)
		go http.Serve(listener, serveMux)
		for {
			if conn, err := net.Dial("tcp", addr); err == nil {
				conn.Close()
				break
			}
			time.Sleep(time.Millisecond * 10)
		}
		return
	}
}

func writeStatus(w http.ResponseWriter, status string) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "    ") // Make life easier for debugging.
	if err := encoder.Encode(responseType{status}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func TestNonExistantUser(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL}
	ok, err := pa.PasswordAuthenticate("bad-user", []byte("dummy-password"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if ok {
		t.Fatalf("non-existant user did not fail")
	}
}

func TestBadPassword(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("bad-password"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if ok {
		t.Fatalf("bad password did not fail")
	}
}

func TestGoodPassword(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("good-password"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if !ok {
		t.Fatalf("good password failed")
	}
}

func TestMfaRequired(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("needs-2FA"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if !ok {
		t.Fatalf("good password needing 2FA failed")
	}
}

func TestUserLockedOut(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("password-expired"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if ok {
		t.Fatalf("expired password suceeded")
	}
}
