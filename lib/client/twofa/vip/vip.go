package vip

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/keymaster/lib/webapi/v0/proto"
)

func doVIPAuthenticate(
	client *http.Client,
	baseURL string,
	logger log.DebugLogger) error {
	logger.Printf("top of doVIPAuthenticate")

	// Read VIP token from client

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter VIP/OTP code: ")
	otpText, err := reader.ReadString('\n')
	otpText = strings.TrimSpace(otpText)
	//fmt.Println(codeText)
	logger.Debugf(1, "codeText:  '%s'", otpText)

	// TODO: add some client side validation that the codeText is actually a six digit
	// integer

	VIPLoginURL := baseURL + "/api/v0/vipAuth"

	form := url.Values{}
	form.Add("OTP", otpText)
	//form.Add("password", string(password[:]))
	req, err := http.NewRequest("POST", VIPLoginURL, strings.NewReader(form.Encode()))

	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	loginResp, err := client.Do(req) //client.Get(targetUrl)
	if err != nil {
		logger.Printf("got error from req")
		logger.Println(err)
		// TODO: differentiate between 400 and 500 errors
		// is OK to fail.. try next
		return err
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != 200 {
		logger.Printf("got error from login call %s", loginResp.Status)
		return err
	}

	loginJSONResponse := proto.LoginResponse{}
	//body := jsonrr.Result().Body
	err = json.NewDecoder(loginResp.Body).Decode(&loginJSONResponse)
	if err != nil {
		return err
	}
	io.Copy(ioutil.Discard, loginResp.Body)

	logger.Debugf(1, "This the login response=%v\n", loginJSONResponse)

	return nil
}
