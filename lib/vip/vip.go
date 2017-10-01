package vip

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"text/template"
	"time"

	"github.com/Symantec/keymaster/lib/util"
)

// The symantec VIP endpoint is very specific on namespaces, and golang's
// XML package is not very good with marshaling namespaces thus we will write
// requests using the text template. but parse them using the xml library
type vipValidateRequest struct {
	RequestId string `xml:"RequestId,attr"`
	TokenId   string `xml:"TokenId"`
	OTP       int    `xml:"OTP`
}

type validateRequestBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		VipValidateRequest vipValidateRequest `xml:"Validate"`
	}
}

const validateRequestTemplate = `<?xml version="1.0" encoding="UTF-8" ?> <SOAP-ENV:Envelope
        xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:ns3="http://www.w3.org/2000/09/xmldsig#"
        xmlns:ns1="http://www.verisign.com/2006/08/vipservice">
        <SOAP-ENV:Body>
                <ns1:Validate Version="2.0" Id="{{.RequestId}}"> 
                     <ns1:TokenId>{{.TokenId}}</ns1:TokenId> 
                     <ns1:OTP>{{printf "%06d" .OTP}}</ns1:OTP>
                </ns1:Validate>
        </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`

type vipResponseStatus struct {
	ReasonCode    string `xml:"ReasonCode,omitempty" json:"ReasonCode,omitempty"`
	StatusMessage string `xml:"StatusMessage,omitempty" json:"StatusMessage,omitempty"`
}

type vipValidateResponse struct {
	RequestId string            `xml:"RequestId,attr"`
	Version   string            `xml:"Version,attr"`
	Status    vipResponseStatus `xml:"Status"`
}

type validateResponseBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		VipValidateResponse vipValidateResponse `xml:"ValidateResponse"`
	}
}

type vipUserInfoRequest struct {
	RequestId string `xml:"requestId`
	UserId    string `xml:"userId"`
}

const userInfoRequestTemplate = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.symantec.com/vip/2011/04/vipuserservices">
   <soapenv:Header/>
   <soapenv:Body>
      <vip:GetUserInfoRequest>
         <vip:requestId>{{.RequestId}}</vip:requestId>
         <vip:userId>{{.UserId}}</vip:userId>
         <!--Optional:-->
         <vip:iaInfo>false</vip:iaInfo>
         <!--Optional:-->
         <vip:includePushAttributes>true</vip:includePushAttributes>
      </vip:GetUserInfoRequest>
   </soapenv:Body>
</soapenv:Envelope>`

type vipResponseBindingDetail struct {
	ReasonCode    string `xml:"bindStatus,omitempty"`
	FriendlyName  string `xml:"friendlyName,omitempty"`
	LastBindTime  string `xml:"lastBindTime,omitempty"`
	LastAuthnTime string `xml:"lastAuthnTime,omitempty"`
	LastAuthnId   string `xml:"lastAuthnId,omitempty"`
}
type vipResponseCredentialBindingDetail struct {
	CredentialId     string                   `xml:"credentialId,omitempty"`
	CredentialType   string                   `xml:"credentialType,omitempty"`
	CredentialStatus string                   `xml:"credentialStatus,omitempty"`
	BindingDetail    vipResponseBindingDetail `xml:"bindingDetail"`
}

type vipResponseGetUserInfo struct {
	RequestId               string                               `xml:"requestId"`
	Status                  string                               `xml:"status"`
	StatusMessage           string                               `xml:"statusMessage"`
	UserId                  string                               `xml:"userId"`
	UserCreationTime        string                               `xml:"userCreationTime"`
	UserStatus              string                               `xml:"userStatus"`
	NumBindings             string                               `xml:"numBindings"`
	CredentialBindingDetail []vipResponseCredentialBindingDetail `xml:"credentialBindingDetail"`
}

type userInfoResponseBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		VipResponseGetUserInfo vipResponseGetUserInfo `xml:"GetUserInfoResponse"`
	}
}

type Client struct {
	Cert               tls.Certificate
	VipServicesURL     string
	VipUserServicesURL string
	RootCAs            *x509.CertPool
}

func NewClient(certPEMBlock, keyPEMBlock []byte) (client Client, err error) {

	client.Cert, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return client, err
	}
	//This is the production url for vipservices
	client.VipServicesURL = "https://vipservices-auth.verisign.com/val/soap"
	client.VipUserServicesURL = "https://userservices-auth.vip.symantec.com/vipuserservices/QueryService_1_7"
	return client, nil
}

func (client *Client) postBytesVip(data []byte, targetURL string, contentType string) ([]byte, error) {
	//two steps... convert data into post data!
	req, err := util.CreateSimpleDataBodyRequest("POST", targetURL, data, contentType)
	if err != nil {
		return nil, err
	}
	// make client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{client.Cert},
		RootCAs:      client.RootCAs,
		MinVersion:   tls.VersionTLS12}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	postResponse, err := httpClient.Do(req)
	if err != nil {
		log.Printf("got error from req")
		log.Println(err)
		// TODO: differentiate between 400 and 500 errors
		// is OK to fail.. try next
		return nil, err
	}
	defer postResponse.Body.Close()
	if postResponse.StatusCode != 200 {
		log.Printf("got error from login call %s", postResponse.Status)
		return nil, err
	}
	return ioutil.ReadAll(postResponse.Body)
}

func (client *Client) postBytesVipServices(data []byte) ([]byte, error) {
	return client.postBytesVip(data, client.VipServicesURL, "application/xml")
}

func (client *Client) postBytesUserServices(data []byte) ([]byte, error) {
	return client.postBytesVip(data, client.VipUserServicesURL, "text/xml")
}

func genNewRequestID() string {
	nBig, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		panic(err)
	}
	return nBig.String()
}

// The response string is only to have some sort of testing
func (client *Client) VerifySingleToken(tokenID string, tokenValue int) (bool, error) {
	requestID := genNewRequestID()
	validateRequest := vipValidateRequest{RequestId: requestID,
		TokenId: tokenID, OTP: tokenValue}
	tmpl, err := template.New("validate").Parse(validateRequestTemplate)
	if err != nil {
		panic(err)
	}
	var requestBuffer bytes.Buffer

	//err = tmpl.Execute(os.Stdout, validateRequest)
	err = tmpl.Execute(&requestBuffer, validateRequest)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("\nbuffer='%s'\n", requestBuffer.String())
	responseBytes, err := client.postBytesVipServices(requestBuffer.Bytes())
	if err != nil {
		return false, err
	}
	var response validateResponseBody
	err = xml.Unmarshal(responseBytes, &response)
	if err != nil {
		fmt.Print(err)
	}
	//fmt.Printf("%+v", response)
	/*
		output, err := xml.MarshalIndent(&response, " ", "    ")
		if err != nil {
			fmt.Printf("error: %v\n", err)
		}

		fmt.Println(output)
	*/
	switch response.Body.VipValidateResponse.Status.ReasonCode {
	case "0000":
		return true, nil
	default:
		return false, nil
	}
	panic("should never have reached this point")
}

func (client *Client) GetActiveTokens(userID string) ([]string, error) {
	requestID := genNewRequestID()
	userInfoRequest := vipUserInfoRequest{RequestId: requestID,
		UserId: userID}

	tmpl, err := template.New("userInfo").Parse(userInfoRequestTemplate)
	if err != nil {
		panic(err)
	}
	var requestBuffer bytes.Buffer

	err = tmpl.Execute(&requestBuffer, userInfoRequest)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("\nbuffer='%s'\n", requestBuffer.String())
	responseBytes, err := client.postBytesUserServices(requestBuffer.Bytes())
	if err != nil {
		return nil, err
	}

	var response userInfoResponseBody
	err = xml.Unmarshal(responseBytes, &response)
	if err != nil {
		fmt.Print(err)
	}
	// TODO verify response requestID matches ours
	//fmt.Printf("%+v", response)
	/*
		output, err := xml.MarshalIndent(&response, " ", "    ")
		if err != nil {
			fmt.Printf("error: %v\n", err)
		}
		fmt.Println(output)
	*/
	var enabledTokenID []string
	for _, credentialBinding := range response.Body.VipResponseGetUserInfo.CredentialBindingDetail {
		//fmt.Printf("\n%+v\n", credentialBinding)
		if credentialBinding.CredentialStatus != "ENABLED" {
			continue
		}
		enabledTokenID = append(enabledTokenID, credentialBinding.CredentialId)
	}

	return enabledTokenID, nil
}

func (client *Client) ValidateUserOTP(userID string, OTPValue int) (bool, error) {
	tokenList, err := client.GetActiveTokens(userID)
	if err != nil {
		return false, err
	}
	if len(tokenList) < 1 {
		return false, nil
	}
	// TODO: replace this loop for a single call in the API
	for _, tokenId := range tokenList {
		ok, err := client.VerifySingleToken(tokenId, OTPValue)
		if err != nil {
			continue
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
