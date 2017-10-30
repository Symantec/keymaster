package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	//"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
	//"golang.org/x/net/context"

	"github.com/mendsley/gojwk"
	//"gopkg.in/dgrijalva/jwt-go.v2"
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
	issuer := "https://" + state.HostIdentity
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

	selfKey.Kid = "1"
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
	State      string `json:"state,omitEmpty"`
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

	//redirectURLString := r.Form.Get("redirect_uri")
	//Dont check for now
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: state.Signer}, nil)
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "")
		return
	}
	codeToken := keymasterdCodeToken{Issuer: "keymasterd", Subject: clientID, IssuedAt: time.Now().Unix()}

	raw, err := jwt.Signed(signer).Claims(codeToken).CompactSerialize()
	if err != nil {
		panic(err)
	}

	fmt.Println(raw)
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

func (state *RuntimeState) idpOpenIDCTokenHandler(w http.ResponseWriter, r *http.Request) {
}
func (state *RuntimeState) idpOpenIDCUserinfoHandler(w http.ResponseWriter, r *http.Request) {
}
