package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Symantec/Dominator/lib/log/testlogger"
	"github.com/Symantec/keymaster/lib/pwauth/okta"
)

func oktaTestWriteStatus(w http.ResponseWriter, status string) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "    ") // Make life easier for debugging.
	response := okta.PrimaryResponseType{Status: status}
	if err := encoder.Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func oktaTestAuthnHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("top of oktaTestAuthnHandler")
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var loginData okta.LoginDataType
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
		oktaTestWriteStatus(w, "SUCCESS")
		return
	case "needs-2FA":
		//oktaTestWriteStatus(w, "MFA_REQUIRED")

		response := okta.PrimaryResponseType{
			StateToken:      "valid-otp",
			ExpiresAtString: "2035-11-03T10:15:57.000Z",
			Status:          "MFA_REQUIRED",
			Embedded: okta.EmbeddedDataResponseType{
				Factor: []okta.MFAFactorsType{
					okta.MFAFactorsType{
						Id:         "someid",
						FactorType: "token:software:totp",
						VendorName: "OKTA"},
				}},
		}
		encoder := json.NewEncoder(w)
		if err := encoder.Encode(response); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case "password-expired":
		oktaTestWriteStatus(w, "PASSWORD_EXPIRED")
		return
	default:
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func oktaTestFactorAuthnHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("top of  oktaTestFactorAuthnHandler")
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// For now we do TOTP only verifyTOTPFactorDataType
	var otpData okta.VerifyTOTPFactorDataType
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&otpData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch otpData.StateToken {
	case "valid-otp":
		oktaTestWriteStatus(w, "SUCCESS")
		return
	case "push-send-waiting":
		response := okta.PushResponseType{
			Status:       "MFA_CHALLENGE",
			FactorResult: "WAITING",
		}
		encoder := json.NewEncoder(w)

		if err := encoder.Encode(response); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	case "push-send-accept":
		oktaTestWriteStatus(w, "SUCCESS")
		return

	default:
		w.WriteHeader(http.StatusUnauthorized)
		return

	}

}

var oktaTestAuthnURL string

func setupTestOtkaServer() {
	if oktaTestAuthnURL != "" {
		return
	}
	if listener, err := net.Listen("tcp", "127.0.0.1:"); err != nil {
		panic(err)
	} else {
		addr := listener.Addr().String()
		oktaTestAuthnURL = "http://" + addr + "/api/v1/authn"
		serveMux := http.NewServeMux()
		serveMux.HandleFunc("/api/v1/authn", oktaTestAuthnHandler)
		serveMux.HandleFunc("/api/v1/authn/factors/", oktaTestFactorAuthnHandler)
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

func TestOkta2FAuthHandlerSuccess(t *testing.T) {

	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	setupTestOtkaServer()
	pa, err := okta.NewPublic("some-domain", testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	err = pa.SetAuthnURL(oktaTestAuthnURL)
	if err != nil {
		t.Fatal(err)
	}
	state.passwordChecker = pa

	ok, err := pa.PasswordAuthenticate("a-user", []byte("needs-2FA"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("should have authenticated")
	}

	//Now we can acutally all the otp call
	// End of Setup
	/*
		authCookie, totpSecret, err := setupTestStateWithTOTPSecret(t, state, AuthTypePassword)
		if err != nil {
			t.Fatal(err)
		}

		otpValue, err := totp.GenerateCode(totpSecret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	*/

	req, err := http.NewRequest("GET", okta2FAauthPath, nil)
	if err != nil {
		t.Fatal(err)
		//return nil, err
	}
	cookieVal, err := state.setNewAuthCookie(nil, "a-user", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	req.AddCookie(&authCookie)

	otpValue := "123456" //does not matter
	data := url.Values{}
	data.Set("OTP", otpValue)
	t.Logf("i testverify url_Data='%+v'", data)
	verifyReq, err := http.NewRequest("POST", okta2FAauthPath, bytes.NewBufferString(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	verifyReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(verifyReq, state.Okta2FAuthHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}

}
