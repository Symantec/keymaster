package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/context"
	//"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

const maxAgeSecondsRedirCookie = 30
const redirCookieName = "oauth2_redir"

const oauth2LoginBeginPath = "/auth/oauth2/login"

func (state *RuntimeState) oauth2DoRedirectoToProviderHandler(w http.ResponseWriter, r *http.Request) {

	if state.Config.Oauth2.Config == nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "error internal")
		log.Println("asking for oauth2, but it is not defined")
		return
	}
	cookieVal, err := genRandomString()
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "error internal")
		log.Println(err)
		return
	}

	// we have to create new context and set redirector...
	expiration := time.Now().Add(time.Duration(maxAgeSecondsRedirCookie) * time.Second)

	stateString, err := genRandomString()
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "error internal")
		log.Println(err)
		return
	}

	cookie := http.Cookie{Name: redirCookieName, Value: cookieVal,
		Expires: expiration, Path: "/", HttpOnly: true}
	http.SetCookie(w, &cookie)

	pending := pendingAuth2Request{
		ExpiresAt: expiration,
		state:     stateString,
		ctx:       context.Background()}
	state.Mutex.Lock()
	state.pendingOauth2[cookieVal] = pending
	state.Mutex.Unlock()
	http.Redirect(w, r, state.Config.Oauth2.Config.AuthCodeURL(stateString), http.StatusFound)
}

func httpGet(client *http.Client, url string) ([]byte, error) {
	r, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	if r.StatusCode >= 300 {
		return nil, fmt.Errorf(string(body))
	}

	//log.Printf("HTTP GET %s: %s %s", url, r.Status, string(body))

	return body, nil
}

func (state *RuntimeState) oauth2RedirectPathHandler(w http.ResponseWriter, r *http.Request) {
	redirCookie, err := r.Cookie(redirCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			state.writeFailureResponse(w, r, http.StatusBadRequest, "Missing setup cookie!")
			log.Println(err)
			return
		}
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "error internal")
		log.Println(err)
		return
	}
	index := redirCookie.Value
	state.Mutex.Lock()
	pending, ok := state.pendingOauth2[index]
	state.Mutex.Unlock()
	if !ok {
		// clear cookie here!!!!
		state.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid setup cookie!")
		log.Println(err)
		return
	}

	if r.URL.Query().Get("state") != pending.state {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}
	//if Debug {
	//log.Printf("req : %+v", r)
	//}
	oauth2Token, err := state.Config.Oauth2.Config.Exchange(pending.ctx, r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("ctx: %+v", pending.ctx)
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	client := state.Config.Oauth2.Config.Client(pending.ctx, oauth2Token)
	//client.Get("...")
	body, err := httpGet(client, state.Config.Oauth2.UserinfoUrl)
	if err != nil {
		log.Printf("fail to fetch %s (%s) ", state.Config.Oauth2.UserinfoUrl, err.Error())
		http.Error(w, "Failed to get userinfo from url: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var data struct {
		Name        string              `json:"name"`
		DisplayName string              `json:"display_name"`
		Login       string              `json:"login"`
		Username    string              `json:"username"`
		Email       string              `json:"email"`
		Attributes  map[string][]string `json:"attributes"`
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Printf("failed to unmarshall userinfo to fetch %s ", body)
		http.Error(w, "Failed to get unmarshall userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}

	//log.Printf("%+v", data)

	// Check if name is there..
	//Make new auth cookie
	cookieVal, err := genRandomString()
	if err != nil {
		state.writeFailureResponse(w, r, http.StatusInternalServerError, "error internal")
		log.Println(err)
		return
	}
	username := data.Name
	expiration := time.Now().Add(time.Duration(maxAgeSecondsAuthCookie) * time.Second)
	savedUserInfo := authInfo{Username: username, ExpiresAt: expiration, AuthType: AuthTypeFederated}
	state.Mutex.Lock()
	state.authCookie[cookieVal] = savedUserInfo
	state.Mutex.Unlock()

	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal, Expires: expiration, Path: "/", HttpOnly: true, Secure: true}

	//use handler with original request.
	http.SetCookie(w, &authCookie)

	// delete peding cookie
	state.Mutex.Lock()
	delete(state.pendingOauth2, index)
	state.Mutex.Unlock()

	//and redirect to profile page
	http.Redirect(w, r, profilePath, 302)

}
