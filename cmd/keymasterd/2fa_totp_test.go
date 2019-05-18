package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Symantec/keymaster/lib/webapi/v0/proto"
	"github.com/pquerna/otp/totp"
)

func TestEncryptDecryptSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	testSecret := "superSecret"
	cipherTexts, err := state.encryptWithPublicKeys([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	plainTextBytes, err := state.decryptWithPublicKeys(cipherTexts)

	if err != nil {
		t.Fatal(err)
	}
	if string(plainTextBytes) != testSecret {
		t.Fatal("values do not match")
	}
}

func TestGenerateNewTOTPSuccess(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	state.Config.Base.AllowedAuthBackendsForWebUI = append(state.Config.Base.AllowedAuthBackendsForWebUI, proto.AuthTypeU2F)

	state.signerPublicKeyToKeymasterKeys()

	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	state.Config.Base.DataDirectory = dir
	err = initDB(state)
	if err != nil {
		t.Fatal(err)
	}

	/// End of setup

	req, err := http.NewRequest("GET", totpGeneratNewPath, nil)
	if err != nil {
		t.Fatal(err)
		//return nil, err
	}
	cookieVal, err := state.setNewAuthCookie(nil, "username", AuthTypeU2F)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	req.AddCookie(&authCookie)

	tokenRR, err := checkRequestHandlerCode(req, state.GenerateNewTOTP, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	resultAccessToken := newTOTPPageTemplateData{}
	body := tokenRR.Result().Body
	err = json.NewDecoder(body).Decode(&resultAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("totpDataToken='%+v'", resultAccessToken)

	//sleep to give time to save?
	time.Sleep(40 * time.Millisecond)

	// now we validate
	otpValue, err := totp.GenerateCode(resultAccessToken.TOTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data := url.Values{}
	data.Set("OTP", otpValue)
	t.Logf("url_Data='%+v'", data)
	validateReq, err := http.NewRequest("POST", totpValidateNewPath, bytes.NewBufferString(data.Encode()))
	if err != nil {
		t.Fatal(err)
		//return nil, err
	}
	validateReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	validateReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(validateReq, state.validateNewTOTP, http.StatusFound)
	if err != nil {
		t.Fatal(err)
	}

}
