package okta

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Symantec/Dominator/lib/log/testlogger"
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

func factorAuthnHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
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
		serveMux.HandleFunc(authPath+"/factors/", factorAuthnHandler)
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
	response := PrimaryResponseType{Status: status}
	if err := encoder.Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func TestNonExistantUser(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{
		authnURL:   authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	ok, err := pa.PasswordAuthenticate("bad-user", []byte("dummy-password"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if ok {
		t.Fatalf("non-existant user did not fail")
	}
}

func TestBadPassword(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("bad-password"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if ok {
		t.Fatalf("bad password did not fail")
	}
}

func TestGoodPassword(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("good-password"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if !ok {
		t.Fatalf("good password failed")
	}
}

func TestMfaRequired(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("needs-2FA"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if !ok {
		t.Fatalf("good password needing 2FA failed")
	}
}

func TestUserLockedOut(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	ok, err := pa.PasswordAuthenticate("a-user", []byte("password-expired"))
	if err != nil {
		t.Fatalf("unpexpected error: %s", err)
	} else if ok {
		t.Fatalf("expired password suceeded")
	}
}

func TestMfaOtpNonExisting(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	valid, err := pa.ValidateUserOTP("someuser", 123456)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("should not have succeeded with no data")
	}
}

func TestMfaOtpExpired(t *testing.T) {
	setupServer()
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	expiredUserCachedData := authCacheData{Expires: time.Now().Add(-3 * time.Second)}
	expiredUser := "expiredUser"
	pa.recentAuth[expiredUser] = expiredUserCachedData
	valid, err := pa.ValidateUserOTP(expiredUser, 123456)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("should not have succeeded with expired user")
	}
}

func TestMfaOTPFailNoValidDevices(t *testing.T) {
	pa := &PasswordAuthenticator{authnURL: authnURL,
		recentAuth: make(map[string]authCacheData),
		logger:     testlogger.New(t),
	}
	response := PrimaryResponseType{
		StateToken: "foo", Status: "MFA_REQUIRED",
		Embedded: EmbeddedDataResponseType{Factor: []MFAFactorsType{
			MFAFactorsType{Id: "someid", FactorType: "token:software:totp"},
			MFAFactorsType{Id: "someid", VendorName: "OKTA"},
		}},
	}
	expiredUserCachedData := authCacheData{Expires: time.Now().Add(60 * time.Second),
		Response: response,
	}
	noOTPCredsUser := "noOTPCredsUser"
	pa.recentAuth[noOTPCredsUser] = expiredUserCachedData
	valid, err := pa.ValidateUserOTP(noOTPCredsUser, 123456)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("should not have succeeded with expired user")
	}
}
