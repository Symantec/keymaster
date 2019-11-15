package okta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Symantec/Dominator/lib/log"
	//"io/ioutil"
	"net/http"
	"time"
)

const (
	authPath               = "/api/v1/authn"
	authEndpointFormat     = "https://%s.okta.com" + authPath
	factorsVerifyPathExtra = "/factors/%s/verify"
)

type verifyTOTPFactorDataType struct {
	StateToken string `json:"stateToken,omitempty"`
	PassCode   string `json:"passCode,omitempty"`
}

type loginDataType struct {
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`
}

type MFAFactorsType struct {
	Id         string `json:"id,omitempty"`
	FactorType string `json:"factorType,omitempty"`
	Provider   string `json:"provider,omitempty"`
	VendorName string `json:"vendorName,omitempty"`
}

type UserProfileType struct {
	Login string `json:"login,omitempty"`
}

type UserInfoType struct {
	Id      string          `json:"id,omitempty"`
	Profile UserProfileType `json:"profile,omitempty"`
}

type EmbeddedDataResponseType struct {
	User   UserInfoType     `json:"user,omitempty"`
	Factor []MFAFactorsType `json:"factors,omitempty"`
}

type PrimaryResponseType struct {
	StateToken      string                   `json:"stateToken,omitempty"`
	ExpiresAtString string                   `json:"expiresAt,omitempty"`
	Status          string                   `json:"status,omitempty"`
	Embedded        EmbeddedDataResponseType `json:"_embedded,omitempty"`
}

type PushResponseType struct {
	ExpiresAtString string                   `json:"expiresAt,omitempty"`
	Status          string                   `json:"status,omitempty"`
	FactorResult    string                   `json:"factorResult,omitempty"`
	Embedded        EmbeddedDataResponseType `json:"_embedded,omitempty"`
}

func newPublicAuthenticator(oktaDomain string, logger log.Logger) (
	*PasswordAuthenticator, error) {
	return &PasswordAuthenticator{
		authnURL:   fmt.Sprintf(authEndpointFormat, oktaDomain),
		logger:     logger,
		recentAuth: make(map[string]authCacheData),
	}, nil
}

func (pa *PasswordAuthenticator) passwordAuthenticate(username string,
	password []byte) (bool, error) {
	loginData := loginDataType{Password: string(password), Username: username}
	body := &bytes.Buffer{}
	encoder := json.NewEncoder(body)
	encoder.SetIndent("", "    ") // Make life easier for debugging.
	if err := encoder.Encode(loginData); err != nil {
		return false, err
	}
	req, err := http.NewRequest("POST", pa.authnURL, body)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("bad status: %s", resp.Status)
	}
	decoder := json.NewDecoder(resp.Body)
	var response PrimaryResponseType
	if err := decoder.Decode(&response); err != nil {
		return false, err
	}
	pa.logger.Printf("oktaresponse=%+v", response)
	switch response.Status {
	case "SUCCESS", "MFA_REQUIRED":
		expires, err := time.Parse(time.RFC3339, response.ExpiresAtString)
		if err != nil {
			expires = time.Now().Add(time.Second * 60)
		}
		toCache := authCacheData{Response: response, Expires: expires}
		//TODO add locking
		pa.Mutex.Lock()
		pa.recentAuth[username] = toCache
		pa.Mutex.Unlock()
		return true, nil
	default:
		return false, nil
	}
}

func (pa *PasswordAuthenticator) validateUserOTP(authUser string, otpValue int) (bool, error) {
	pa.Mutex.Lock()
	userData, ok := pa.recentAuth[authUser]
	pa.Mutex.Unlock()
	if !ok {
		return false, nil
	}
	//TODO: check for expiration
	if userData.Expires.Before(time.Now()) {
		pa.logger.Printf("expired Value!!! expires=%s", userData.Expires)
		pa.Mutex.Lock()
		delete(pa.recentAuth, authUser)
		pa.Mutex.Unlock()
		return false, nil

	}

	for _, factor := range userData.Response.Embedded.Factor {
		if !(factor.FactorType == "token:software:totp" && factor.VendorName == "OKTA") {
			continue
		}
		authURL := fmt.Sprintf(pa.authnURL+factorsVerifyPathExtra, factor.Id)
		verifyStruct := verifyTOTPFactorDataType{
			StateToken: userData.Response.StateToken,
			PassCode:   fmt.Sprintf("%06d", otpValue),
		}
		pa.logger.Printf("AuthURL=%s", authURL)
		pa.logger.Printf("totpVerifyStruct=%+v", verifyStruct)
		body := &bytes.Buffer{}
		encoder := json.NewEncoder(body)
		encoder.SetIndent("", "    ") // Make life easier for debugging.
		if err := encoder.Encode(verifyStruct); err != nil {
			return false, err
		}
		req, err := http.NewRequest("POST", authURL, body)
		if err != nil {
			return false, err
		}
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			return false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("bad status: %s", resp.Status)
		}
		decoder := json.NewDecoder(resp.Body)
		var response PrimaryResponseType
		if err := decoder.Decode(&response); err != nil {
			return false, err
		}
		pa.logger.Printf("oktaresponse=%+v", response)
		if response.Status != "SUCCESS" {
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

func (pa *PasswordAuthenticator) validateUserPush(authUser string) (PushResponse, error) {
	pa.Mutex.Lock()
	userData, ok := pa.recentAuth[authUser]
	pa.Mutex.Unlock()
	if !ok {
		return PushResponseRejected, nil
	}
	//TODO: check for expiration
	if userData.Expires.Before(time.Now()) {
		pa.logger.Printf("expired Value!!! expires=%s", userData.Expires)
		pa.Mutex.Lock()
		delete(pa.recentAuth, authUser)
		pa.Mutex.Unlock()
		return PushResponseRejected, nil

	}
	for _, factor := range userData.Response.Embedded.Factor {
		if !(factor.FactorType == "push" && factor.VendorName == "OKTA") {
			continue
		}
		authURL := fmt.Sprintf(pa.authnURL+factorsVerifyPathExtra, factor.Id)
		verifyStruct := verifyTOTPFactorDataType{
			StateToken: userData.Response.StateToken,
		}
		pa.logger.Printf("AuthURL=%s", authURL)
		pa.logger.Printf("totpVerifyStruct=%+v", verifyStruct)
		body := &bytes.Buffer{}
		encoder := json.NewEncoder(body)
		encoder.SetIndent("", "    ") // Make life easier for debugging.
		if err := encoder.Encode(verifyStruct); err != nil {
			return PushResponseRejected, err
		}
		req, err := http.NewRequest("POST", authURL, body)
		if err != nil {
			return PushResponseRejected, err
		}
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return PushResponseRejected, err
		}
		defer resp.Body.Close()
		/*
			if resp.StatusCode == http.StatusForbidden {
				return false, nil
			}
		*/

		if resp.StatusCode != http.StatusOK {
			return PushResponseRejected, fmt.Errorf("bad status: %s", resp.Status)
		}
		decoder := json.NewDecoder(resp.Body)
		var response PushResponseType
		if err := decoder.Decode(&response); err != nil {
			return PushResponseRejected, err
		}
		pa.logger.Printf("oktaresponse=%+v", response)
		switch response.Status {
		case "SUCCESS":
			return PushResponseApproved, nil
		case "MFA_CHALLENGE":
			break
		default:
			pa.logger.Printf("invalid status")
			return PushResponseRejected, nil
		}

		switch response.FactorResult {
		case "WAITING":
			return PushResponseWaiting, nil
		case "TIMEOUT":
			return PushResonseTimeout, nil
		default:
			return PushResponseRejected, nil
		}

	}
	return PushResponseRejected, nil
}
