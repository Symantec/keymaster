package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"image/png"
	"net/http"
	"strconv"
	"time"

	"github.com/Symantec/keymaster/lib/instrumentedwriter"
	"github.com/pquerna/otp/totp"
)

const labelRSA = "totp:rsa:"
const totpGeneratNewPath = "/totp/GenerateNew/"
const totpValidateNewPath = "/totp/ValidateNew/"

func (state *RuntimeState) encryptWithPublicKeys(clearTextMessage []byte) ([][]byte, error) {
	var cipherTexts [][]byte
	for _, key := range state.KeymasterPublicKeys {
		logger.Debugf(3, "encryptWithPublicKeys: On internal loop with type %T", key)
		// TODO: do Handle ECC keys
		rsaPubKey, ok := key.(*rsa.PublicKey)
		if ok {
			label := []byte(labelRSA)
			rng := rand.Reader
			ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, rsaPubKey, clearTextMessage, label)
			if err != nil {
				logger.Printf("Error from encryption: %s\n", err)
				return nil, err
			}
			cipherTexts = append(cipherTexts, ciphertext)
			continue
		}
	}
	if len(cipherTexts) < 1 {
		return nil, errors.New("cannot encrypt with any key")
	}
	return cipherTexts, nil
}

func (state *RuntimeState) decryptWithPublicKeys(cipherTexts [][]byte) ([]byte, error) {
	logger.Debugf(5, "signer type=%T", state.Signer)
	for _, cipherText := range cipherTexts {
		rsaPrivateKey, ok := state.Signer.(*rsa.PrivateKey)
		if ok {
			label := []byte(labelRSA)
			rng := rand.Reader
			plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, rsaPrivateKey, cipherText, label)
			if err != nil {
				logger.Printf("Error from decryption: %s\n", err)
				continue
			}
			return plaintext, nil
		}

	}

	return nil, errors.New("Cannot decrypt Message")
}

func (state *RuntimeState) GenerateNewTOTP(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	// TODO: think if we are going to allow admins to register these tokens
	authUser, _, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)

	// TODO: check if TOTP is even enabled.

	// TODO: check for method, we should only allow POST requests

	profile, _, fromCache, err := state.LoadUserProfile(authUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		state.writeFailureResponse(w, r, http.StatusServiceUnavailable, "DB in cached state, cannot create new TOTP now")
		return
	}
	logger.Debugf(2, "%v", profile)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "keymaster-totp", //TODO: get the actual name
		AccountName: authUser,
	})
	if err != nil {
		logger.Printf("generating new key error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	encryptedKeys, err := state.encryptWithPublicKeys([]byte(key.Secret()))
	if err != nil {
		logger.Printf("Encrypting key error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	profile.PendingTOTPSecret = &encryptedKeys
	err = state.SaveUserProfile(authUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	logger.Debugf(3, "Generate TOTP: profile=%+v", profile)

	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)
	base64Image := base64.StdEncoding.EncodeToString(buf.Bytes())

	logger.Debugf(10, "base64image=%s", base64Image)

	// We need custom CSP policy to allow embedded images
	w.Header().Set("Content-Security-Policy", "default-src 'self' ;img-src 'self'  data: ;style-src 'self' fonts.googleapis.com 'unsafe-inline'; font-src fonts.gstatic.com fonts.googleapis.com")

	displayData := newTOTPPageTemplateData{
		AuthUsername:    authUser,
		Title:           "New TOTP Generation", //TODO: maybe include username?
		TOTPSecret:      key.Secret(),
		TOTPBase64Image: template.HTML("<img src=\"data:image/png;base64," + base64Image + "\" alt=\"beastie.png\" scale=\"0\" />"),
	}

	returnAcceptType := getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		err = state.htmlTemplate.ExecuteTemplate(w, "newTOTPage", displayData)
		if err != nil {
			logger.Printf("Failed to execute %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	default:
		json.NewEncoder(w).Encode(displayData)
	}
	return
}

func (state *RuntimeState) validateNewTOTP(w http.ResponseWriter, r *http.Request) {
	if state.sendFailureToClientIfLocked(w, r) {
		return
	}
	// TODO: think if we are going to allow admins to register these tokens
	authUser, _, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Debugf(1, "%v", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)

	if r.Method != "POST" {
		logger.Printf("Wanted Post got='%s'", r.Method)
		state.writeFailureResponse(w, r, http.StatusMethodNotAllowed, "")
		return
	}
	err = r.ParseForm()
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing form")
		return
	}
	var OTPString string
	if val, ok := r.Form["OTP"]; ok {
		if len(val) > 1 {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Just one OTP Value allowed")
			logger.Printf("Login with multiple OTP Values")
			return
		}
		OTPString = val[0]
	}
	_, err = strconv.Atoi(OTPString)
	if err != nil {
		logger.Println(err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Error parsing OTP value")
	}

	profile, _, fromCache, err := state.LoadUserProfile(authUser)
	if err != nil {
		logger.Printf("loading profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	if fromCache {
		logger.Printf("DB is being cached and requesting registration aborting it")
		http.Error(w, "db backend is offline for writes", http.StatusServiceUnavailable)
		return
	}

	if profile.PendingTOTPSecret == nil {
		logger.Printf("No pending Secrets")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "No pending Secrets")
		return
	}

	// TODO: The encrypted value MUST have also an expiration
	encryptedKeys := profile.PendingTOTPSecret

	clearTextKey, err := state.decryptWithPublicKeys(*encryptedKeys)
	if err != nil {
		logger.Printf("Decrypting secret error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	valid := totp.Validate(OTPString, string(clearTextKey))
	if !valid {
		//render try again vailidate page, with an error message
		logger.Printf("Invalid Entry")
		w.WriteHeader(http.StatusBadRequest)
		displayData := newTOTPPageTemplateData{
			AuthUsername: authUser,
			Title:        "Validate New TOTP Generation", //TODO: maybe include username?
			ErrorMessage: "Invalid TOTP value, please try again",
		}
		returnAcceptType := getPreferredAcceptType(r)
		switch returnAcceptType {
		case "text/html":
			err = state.htmlTemplate.ExecuteTemplate(w, "newTOTPage", displayData)
			if err != nil {
				logger.Printf("Failed to execute %v", err)
				//http.Error(w, "error", http.StatusInternalServerError)
				return
			}
		default:
			json.NewEncoder(w).Encode(displayData)
		}
		return

	}
	// TODO: check if same secret already there

	newTOTPAuthData := totpAuthData{
		CreatedAt:       time.Now(),
		EncryptedSecret: *profile.PendingTOTPSecret,
		ValidatorAddr:   r.RemoteAddr,
	}
	newIndex := newTOTPAuthData.CreatedAt.Unix()
	profile.TOTPAuthData[newIndex] = &newTOTPAuthData
	profile.PendingTOTPSecret = nil
	err = state.SaveUserProfile(authUser, profile)
	if err != nil {
		logger.Printf("Saving profile error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	//redirect to profile page?
	http.Redirect(w, r, profilePath, 302)
}
