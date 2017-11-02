package main

import (
	"bytes"
	//"crypto"
	//"crypto/sha256"
	"encoding/json"
	//"errors"
	"fmt"
	//"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	//"golang.org/x/net/context"
	"github.com/mendsley/gojwk"
	//"gopkg.in/dgrijalva/jwt-go.v2"
	//"golang.org/x/crypto/ssh"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

//For minimal openid connect interaface and easy config we need 5 enpoints
// 1. Discovery Document -> so that consumers need only 3 conf values
// 2. jwks_uri -> where the keys to decrypt document can be found
// 3. authorization_endpoint - > OAUth2 authorization endpoint
// 4. token_endpoint
// 5. userinfo endpoint.

const idpOpenIDCConfigurationDocumentPath = "/.well-known/openid-configuration"
const idpOpenIDCJWKSPath = "/idp/oauth2/jwks"
const idpOpenIDCAuthorizationPath = "/idp/oauth2/authorize"
const idpOpenIDCTokenPath = "/idp/oauth2/token"
const idpOpenIDCUserinfoPath = "/idp/oauth2/userinfo"

// From: https://openid.net/specs/openid-connect-discovery-1_0.html
// We only put required OR implemented fields here
type openIDProviderMetadata struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndoint           string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint"`
	JWKSURI                string   `json:"jwks_uri"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	SubjectTypesSupported  []string `json:"subject_types_supported"`
	IDTokenSigningAlgValue []string `json:"id_token_signing_alg_values_supported"`
}

func (state *RuntimeState) idpOpenIDCDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	/*
		issuer := "https://" + state.HostIdentity
		//this is a hack..
		if state.Config.Base.HttpAddress != ":443" {
			issuer = issuer + state.Config.Base.HttpAddress
		}
	*/
	issuer := state.idpGetIssuer()
	metadata := openIDProviderMetadata{
		Issuer:                 issuer,
		AuthorizationEndpoint:  issuer + idpOpenIDCAuthorizationPath,
		TokenEndoint:           issuer + idpOpenIDCTokenPath,
		UserInfoEndpoint:       issuer + idpOpenIDCUserinfoPath,
		JWKSURI:                issuer + idpOpenIDCJWKSPath,
		ResponseTypesSupported: []string{"code"},               // We only support authorization code flow
		SubjectTypesSupported:  []string{"pairwise", "public"}, // WHAT is THIS?
		IDTokenSigningAlgValue: []string{"RS256"}}
	// need to agree on what scopes we will support

	b, err := json.Marshal(metadata)
	if err != nil {
		log.Fatal(err)
	}

	var out bytes.Buffer
	json.Indent(&out, b, "", "\t")
	//w.Header.Add("Content-Type", "application/json")
	w.Header().Set("Content-Type", "application/json")
	out.WriteTo(w)
}

// Need to improve this to account for adding the other signers here.
func (state *RuntimeState) idpOpenIDCJWKSHandler(w http.ResponseWriter, r *http.Request) {
	selfKey, err := gojwk.PublicKey(state.Signer.Public())
	if err != nil {
		log.Fatal(err)
	}

	selfKey.Kid, err = getKeyFingerprint(state.Signer.Public())
	if err != nil {
		log.Fatal(err)
	}
	mkey, err := gojwk.Marshal(selfKey)
	if err != nil {
		log.Fatal(err)
	}
	// hacky for now
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"keys\": [%s]  }", string(mkey))
}

type keymasterdCodeToken struct {
	Issuer     string `json:"iss"` //keymasterd
	Subject    string `json:"sub"` //clientID
	IssuedAt   int64  `json:"iat"`
	Expiration int64  `json:"exp"`
	Username   string `json:"username"`
	AuthLevel  int64  `json:"auth_level"`
	Nonce      string `json:"nonce,omitEmpty"`
	//State      string `json:"state,omitEmpty"`
	//ClientID    string `json:"client_id"`
	//RedirectURI string `json:"redirect_uri"`
	Scope string `json:"scope"`
}

func (state *RuntimeState) idpOpenIDCAuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	// We are now at exploration stage... and will require pre-authed clients.
	authUser, _, err := state.checkAuth(w, r, state.getRequiredWebUIAuthLevel())
	if err != nil {
		logger.Printf("%v", err)
		return
	}
	logger.Printf("AuthUser of idc auth: %s", authUser)
	// requst MUST be a GET or POST
	if !(r.Method == "GET" || r.Method == "POST") {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Method for Auth Handler")
		return
	}
	err = r.ParseForm()
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	logger.Printf("Auth request =%+v", r)
	//logger.Printf("IDC auth from=%v", r.Form)
	if r.Form.Get("response_type") != "code" {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Unsupported or Missing response_type for Auth Handler")
		return
	}

	clientID := r.Form.Get("client_id")
	if clientID == "" {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Empty cleint_id for Auth Handler")
		return
	}
	scope := r.Form.Get("scope")
	validScope := false
	for _, requestedScope := range strings.Split(scope, " ") {
		if requestedScope == "openid" {
			validScope = true
		}
	}
	if !validScope {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid scope value for Auth Handler")
		return
	}

	requestRedirectURLString := r.Form.Get("redirect_uri")
	//Dont check for now
	signerOptions := (&jose.SignerOptions{}).WithType("JWT")
	//signerOptions.EmbedJWK = true
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: state.Signer}, signerOptions)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	codeToken := keymasterdCodeToken{Issuer: state.idpGetIssuer(), Subject: clientID, IssuedAt: time.Now().Unix()}
	codeToken.Scope = scope
	codeToken.Expiration = time.Now().Unix() + 3600*16
	codeToken.Username = authUser
	codeToken.Nonce = r.Form.Get("nonce")

	raw, err := jwt.Signed(signer).Claims(codeToken).CompactSerialize()
	if err != nil {
		panic(err)
	}

	redirectPath := fmt.Sprintf("%s?code=%s&state=%s", requestRedirectURLString, raw, r.Form.Get("state"))
	http.Redirect(w, r, redirectPath, 302)
	//logger.Printf("raw jwt =%v", raw)
}

type openIDConnectIDToken struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   []string `json:"aud"`
	Expiration int64    `json:"exp"`
	IssuedAt   int64    `json:"iat"`
	AuthTime   int64    `json:"auth_time,omitempty"` //Time of Auth
	Nonce      string   `json:"nonce,omitempty"`
}

type accessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:expires_in`
	IDToken     string `json:"id_token"`
}

type userInfoToken struct {
	Username   string `json:"username"`
	Scope      string `json:"scope"`
	Expiration int    `json:"exp"`
	Type       string `json:"type"`
}

func (state *RuntimeState) idpOpenIDCTokenHandler(w http.ResponseWriter, r *http.Request) {

	// MUST be POST https://openid.net/specs/openid-connect-core-1_0.html 3.1.3.1
	if !(r.Method == "POST") {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Method for Auth Handler")
		return
	}
	err := r.ParseForm()
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid grant type")
		return
	}
	requestRedirectURLString := r.Form.Get("redirect_uri")
	if requestRedirectURLString == "" {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid redirect uri")
		return
	}
	logger.Printf("token request =%+v", r)
	codeString := r.Form.Get("code")
	if codeString == "" {
		state.writeFailureResponse(w, r, http.StatusBadRequest, "nil code")
		return

	}
	tok, err := jwt.ParseSigned(codeString)
	if err != nil {
		logger.Printf("err=%s", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "bad code")
		return
	}
	logger.Printf("tok=%+v", tok)
	//out := jwt.Claims{}
	keymasterToken := keymasterdCodeToken{}
	//if err := tok.Claims(state.Signer.Public(), &keymasterToken); err != nil {
	if err := state.JWTClaims(tok, &keymasterToken); err != nil {
		logger.Printf("err=%s", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "bad code")
		return
	}
	logger.Printf("out=%+v", keymasterToken)

	//now is time to extract the values..

	//formClientID := r.Form.Get("clientID")
	logger.Printf("%+v", r)

	clientID, pass, ok := r.BasicAuth()
	if !ok {
		state.writeFailureResponse(w, r, http.StatusUnauthorized, "")
		//toLoginOrBasicAuth(w, r)
		//err := errors.New("check_Auth, Invalid or no auth header")
		//return "", AuthTypeNone, err
		return
	}
	logger.Printf("username=%s, pass%s", clientID, pass)
	signerOptions := (&jose.SignerOptions{}).WithType("JWT")
	kid, err := getKeyFingerprint(state.Signer.Public())
	if err != nil {
		log.Fatal(err)
	}

	signerOptions = signerOptions.WithHeader("kid", kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: state.Signer}, signerOptions)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}

	idToken := openIDConnectIDToken{Issuer: state.idpGetIssuer(), Subject: keymasterToken.Username, Audience: []string{clientID}}
	idToken.Nonce = keymasterToken.Nonce
	idToken.Expiration = time.Now().Unix() + 3600*16
	idToken.IssuedAt = time.Now().Unix()

	signedIdToken, err := jwt.Signed(signer).Claims(idToken).CompactSerialize()
	if err != nil {
		panic(err)
	}
	logger.Printf("raw=%s", signedIdToken)

	userinfoToken := userInfoToken{Username: keymasterToken.Username, Scope: keymasterToken.Scope}
	signedAccessToken, err := jwt.Signed(signer).Claims(userinfoToken).CompactSerialize()
	if err != nil {
		panic(err)
	}

	// The access token will be yet another jwt.
	outToken := accessToken{AccessToken: signedAccessToken, TokenType: "Bearer", ExpiresIn: 3600, IDToken: signedIdToken}

	// and write the json output
	b, err := json.Marshal(outToken)
	if err != nil {
		log.Fatal(err)
	}

	var out bytes.Buffer
	json.Indent(&out, b, "", "\t")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	out.WriteTo(w)

}

type openidConnectUserInfo struct {
	Subject           string `json:"sub"`
	Name              string `json:"name"`
	Username          string `json:"username,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
}

func (state *RuntimeState) idpOpenIDCUserinfoHandler(w http.ResponseWriter, r *http.Request) {

	if !(r.Method == "GET" || r.Method == "POST") {
		logger.Printf("Invalid Method for Userinfo Handler")
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Method for Userinfo Handler")
		return
	}
	logger.Printf("%+v", r)
	var accessToken string
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		logger.Printf("%s", authHeader)
		splitHeader := strings.Split(authHeader, " ")
		if len(splitHeader) == 2 {
			if splitHeader[0] == "Bearer" {
				accessToken = splitHeader[1]
			}
		}
	}
	if accessToken == "" {
		//logger.Printf("")
		err := r.ParseForm()
		if err != nil {
			state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
			return
		}
		accessToken = r.Form.Get("access_token")
	}
	logger.Printf("access_token='%s'", accessToken)

	if accessToken == "" {
		logger.Printf("access_token='%s'", accessToken)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Missing access token")
		return
	}

	tok, err := jwt.ParseSigned(accessToken)
	if err != nil {
		logger.Printf("err=%s", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "bad access token")
		return
	}
	logger.Printf("tok=%+v", tok)

	parsedAccessToken := userInfoToken{}
	//if err := tok.Claims(state.Signer.Public(), &parsedAccessToken); err != nil {
	if err := state.JWTClaims(tok, &parsedAccessToken); err != nil {
		logger.Printf("err=%s", err)
		state.writeFailureResponse(w, r, http.StatusBadRequest, "bad code")
		return
	}
	logger.Printf("out=%+v", parsedAccessToken)

	userInfo := openidConnectUserInfo{Subject: parsedAccessToken.Username, Email: "username@example.com", Name: "username"}
	// and write the json output
	b, err := json.Marshal(userInfo)
	if err != nil {
		log.Fatal(err)
	}

	var out bytes.Buffer
	json.Indent(&out, b, "", "\t")
	w.Header().Set("Content-Type", "application/json")
	out.WriteTo(w)
}
