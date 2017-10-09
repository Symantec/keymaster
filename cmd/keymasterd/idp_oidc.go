package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	//"io/ioutil"
	"log"
	"net/http"
	//"strings"
	//"time"
	//"golang.org/x/net/context"
	"github.com/mendsley/gojwk"
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
		ResponseTypesSupported: []string{"code"},
		SubjectTypesSupported:  []string{"pairwise", "public"}, // WHAT is THIS?
		IDTokenSigningAlgValue: []string{"RS256"}}

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

func (state *RuntimeState) idpOpenIDCAuthorizationHandler(w http.ResponseWriter, r *http.Request) {
}
func (state *RuntimeState) idpOpenIDCTokenHandler(w http.ResponseWriter, r *http.Request) {
}
func (state *RuntimeState) idpOpenIDCUserinfoHandler(w http.ResponseWriter, r *http.Request) {
}
