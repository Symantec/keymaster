package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	//"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// copied from lib/certgen/cergen_test.go
const testSignerPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAv2J464KoYbODMIbtkTV58g6/0QTdUIYgOwnzPdaMNVtCOxTi
QDIWEbzqv1HEP9hfzuaSKHUHs/91e4Jj2qZghSwPHLG7TKzu+/CRK9sa9jvoGEVx
g6yjibPndTGuLVptZCcOIcHEXViP4iraI6dybiGDlmeF92WQJdI7l4Esg4W4Wp17
JFWNHbylKoFB0fe2b4q5pzaXMBwNue4BKKvua51NBctRy4LZYwiGvVJplEbjBU7v
wCAS0X4m72y2JvKog9/HfGKo2rZ9se0wFe9mMkjj0wuKkDh91pOzsBZ/0PW0zHci
2q9yJVxF0b41e9+raXa8kvRjxF7EEAuUr9Ov2wIDAQABAoIBAQCPmP4rjyRx8jQr
9AFKY7p00XZBCYpZAdorEiMtMc6PtkJyfA/qpOoEMyBbnqlGUj5Iyp29t1mpR7LJ
kiMECrP/F/jaycxEErlZ1b3HDyYivP4/P9OVPbKS/qZbO4R5yRCtBdTHpVCFzY5f
31E/UUM9uO23q0NMRisrBZvq6GQS5bPIbV/JHJIj1Xd65pZQKQMlRKdXnQGWANV6
4i6Yjcy8v/hqI4wxiwxGlAC26+d1Ow4sdHsMiRmA31vhJNMktdVfT3emyiIlLwoi
Oolbak9CpV2bvtN6iL0Hy4ek0TZp7QPzp7MT4Bhcf8jj9ykxL51SplJoOh2xVwfF
U4aaf1mJAoGBAPKP3an+LFPl8+Re8kVJay7JQrNOIzuoDsDbfhVQMJ9KuodGBz8U
YaUeK8iYZFRuYB/OuIqoDiFnlcdC441+M9VRMhuKwq1rLUOz92esyfiwn8CNzEnT
bJKDPvLocGtpRrN+2iqy+/ySk0IX7NUtsB2/8KXLXImY3ecTafjjqv4dAoGBAMn8
yM03RuBOTXsxWRjPIGBniH0mZG+7KdEbBGmhvhoZ8+uneXJvNL+0xswnf6S4r1tm
mEWM1PldE0tPbRID148Mm2H+tCv7IwtpXSRTKEb175Xkj+pIcFtBC1bkGdNv8DJW
BdkKVnDD2h6rND1IOHatBNjW+CO+2R3aZPUxBGRXAoGAfWu0QzTg+NS7QodxoC/x
UvTQH2S0xSEF1+TmkeCv832xa0bjclN4lec+3m8l2Z5k5619MHzrKYylHq5QeRYb
eR6N2T3rob38XriMobfviz7Qq8DmM/o1dqCUiQd1MaTy4NcjudZog1XK/O7gD+6a
1RctOJ0pkSBRBS29qusVvGUCgYEAtvsDRbUvxf/pfRKlbi4lXHAuW4GuNvHM3hul
kbPurWKZcAAVqy9HD+xKs6OMpMKSSTDV/RupzAUfd3gKjOliG7sGAG5m9fjaNHpM
4J1cvXwKgTW/kjPxZRm1lg+pvbuIU3FOduJAkIM8U9Aw0NteG1R+MZn8zRUVR1AT
aXPwUJ0CgYEA6Fpq8/MFJyzpcvlxkZSfZOVFmkDbE3+UYkB0WAR0X7sTdN74nrTf
RnmMXhcdJ7cCPL6LJpN82h62XrLVwl7zEBXnVfhSsXil1yYHHI5sGXbUFRzaNXNl
KgeanQGV/sG+nd/67uvHhZbifHVDY/ifsNBnYrlpu6q3p+zhQydfkLE=
-----END RSA PRIVATE KEY-----`

// same as above but symmtrically gpg encrypted with password
// "password"
const encryptedTestSignerPrivateKey = `-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.0.22 (GNU/Linux)

jA0EAwMCcbfT9PQ87i/ZyeqXE353E4hV/gIydHlfgw7G7ybSniVuLGR8C9WpBx0o
znCGTj4qL2HKgw3wHsahK3LtMioiVmRwnzcfOW+RJxpPZL04NIb+dlkIOodZ5ci2
vqkhe23TdTHTz4XhScWe+0K+LxXeNWn5FjuApMxGnQpCbHtxnd5hTiMTTRKualZG
CPDnqy6ngXkFe5bu5nP6jsqTiWe/qZceng6MYKGHwZRZrBT1oZoL0JYXiBFVz/31
QiZA+24eTRiWcru/1d3HTc34NnHm9MTCH855Y9WtSsQq7y9Lu34NLqEuxdvhYtN9
a6jn4WASuXQgiA7kiOfH3F/9wVlnmXCgi9pvrSsiIhe3ve7NwhRva5fwj4c9BbiD
ZhwyvUC9743owKG6djk06k9cCVooIJnRwmtILKmizRqoJifepkyoJyNtKbJO3MMA
UV2D6MTqH6p29Jdud6VzmVvC6ka3GbHmrsV/I7axqwRV9cA8HwOl+i/7ZqX+ehKG
3DAySJwE3v5NrV2XRk5DUhFrfgHIziFJaa6JOO2M4wBVn9n+hhX0a3czGdM1dnA/
5ncVjJ4M+n4KmEkHAxGrIfM3+egv4arClBo5Y91ltwZLdmh5iKPOUN4x9hpA/ICy
2qSW80qVR5KNgW8vn4CW8MSjTHPMa6Upds42lKUJDYeXkEqGCpvt9izdEjTnnCrq
mRJoGO1N9Oz4ih8JRXaAVCbNbUteZmYREfGfbd8L01Zj6JQCm40G2i/5b0C79yXA
F1RtTaLSHg1guL243SMfTc+83FQ3epAJnJNaYLVKzCrIfd1Ez+bX9N99Zcik64Rx
kIGLOm1ys/bYerONpMSvRDQYYp6uHKUL7Fp1WajCVGR5L0GyHvirvA73R5mMdS/Q
8tWelKu2V6bAhSKElSHHnmToWTiJS98V/hW8RIT9kkqSdecX87UisH7WOZR/JIql
uo1ezuSO0L6gKLKUCzIqK49ppbVXGHkLYP5/a4qBwGU8v89SihLoA4obQuN/eV0n
VaPC3FXN2P1OM4q981tDxDcrDtZ31Z3uz+N8CZPaalQJLzCY2OKUsvembQuFD2l6
S9f6IWGZXhYq8BRw0+VEcnAf8oG0AWlAycAAkAaLxOj53dJLP8sK9q0M+M+yimCB
72hZg4HFgVzXsDcmYtkjlvOiOrXBUDXwzLbEDZuzCYposdWnnam2TMzj6d+psOvJ
WYyl70ZLZUs4RHIq4MB9fZyd1Oo3S/IvVbbfyaFVmvGIaGdZJ1pYFYK2USpfhrKj
ucfnXtWr9UHnSEiof9dLAtwYo2jLvs58+142gzJH7L3DYpI9kmQtf0i+gEyZ+fgN
3CRFCAP8ancFcgFeCXiFYUlPZz0pnEK8jSP7OVhEEICWwHSlD8qauT35xPeL2zf3
HWHTf9Fm+hd9AMWz6izgUbFIw4iLVmvp4FYc0C8SWUyUBasU2DKsjJH8Q1/Vy78h
hf80/+FrB8U3ETJV/T2dGFuFwOmSeaMNGOlK2OBM+Ch4lE1xiWPcp/yXzhLU/J92
vWYfnWNomDDFGad4eR8JPAT7sHJ20t8ihGMOKkfQDHt64F4pE0a3h35Tw9xxZpL0
bNcwEKLlQzbXItC0sqiQrgDNZZI8ZDEmL9FK42IKhoH7cL2siTDKDU0KmxJcbSKJ
B6TBdSkIkx6wGwrmAgtQ7D3A1PdFVDOdgQ72qWXzcDBAa5+ev9XefLdfmcbe726o
H75JiRm3pbOn5cE5lux680VJLITirQRFwR1/8lYfTLBisX44VIdmFRcFQDXrRqBU
WUGURkRA8g==
=ym0B
-----END PGP MESSAGE-----`

const testUserPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI09fpMWTeYw7/EO/+FywS/sghNXdTeTWxX7K2N17owsQJX8s76LGVIdVeYrWg4QSmYlpf6EVSCpx/fbCazrsG7FJVTRhExzFbRT9asmvzS+viXSbSvnavhOz/paihyaMsVPKVv24vF6MOs8DgfwehcKCPjKoIPnlYXZaZcy05KOcZmsvYu2kNOP6sSjDFF+ru+T+DLp3DUGw+MPr45IuR7iDnhXhklqyUn0d7ou0rOHXz9GdHIzpr+DAoQGmTDkpbQEo067Rjfu406gYL8pVFD1F7asCjU39llQCcU/HGyPym5fa29Nubw0dzZZXGZUVFalxo02YMM7P9I6ZjeCsv camilo_viecco1@mon-sre-dev.ash2.symcpe.net`

// This DB has user 'username' with password 'password'
const userdbContent = `username:$2y$05$D4qQmZbWYqfgtGtez2EGdOkcNne40EdEznOqMvZegQypT8Jdz42Jy`

func createBasicAuthRequstWithKeyBody(method, urlStr, username, password string) (*http.Request, error) {
	//create attachment....
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	//
	fileWriter, err := bodyWriter.CreateFormFile("pubkeyfile", "somefilename.pub")
	if err != nil {
		fmt.Println("error writing to buffer")
		//t.Fatal(err)
		return nil, err
	}
	fh := strings.NewReader(testUserPublicKey)

	//iocopy
	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		//t.Fatal(err)
		return nil, err
	}

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest(method, urlStr, bodyBuf)
	if err != nil {
		//t.Fatal(err)
		return nil, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", contentType)

	return req, nil
}

func setupPasswdFile() (f *os.File, err error) {
	tmpfile, err := ioutil.TempFile("", "userdb_test")
	if err != nil {
		return nil, err
	}
	//from this moment on.. we need to remove the tmpfile only on error conditions

	if _, err := tmpfile.Write([]byte(userdbContent)); err != nil {
		os.Remove(tmpfile.Name())
		return nil, err
	}
	if err := tmpfile.Close(); err != nil {
		os.Remove(tmpfile.Name())
		return nil, err
	}
	return tmpfile, nil
}

func TestSuccessFullSigning(t *testing.T) {
	var state RuntimeState
	//load signer
	signer, err := ssh.ParsePrivateKey([]byte(testSignerPrivateKey))
	if err != nil {
		//log.Printf("Cannot parse Priave Key file")
		//return runtimeState, err
		t.Fatal(err)
	}
	state.Signer = &signer

	passwdFile, err := setupPasswdFile()
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(passwdFile.Name()) // clean up
	state.Config.Base.Htpasswd_Filename = passwdFile.Name()

	// Get request
	req, err := createBasicAuthRequstWithKeyBody("POST", "/certgen/username", "username", "password")
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.certGenHandler)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	/*
		// Check the response body is what we expect.
		expected := `{"alive": true}`
		if rr.Body.String() != expected {
			t.Errorf("handler returned unexpected body: got %v want %v",
				rr.Body.String(), expected)
		}

	*/
}

func TestInjectingSecret(t *testing.T) {
	var state RuntimeState
	passwdFile, err := setupPasswdFile()
	if err != nil {
		t.Fatal(err)
	}
	state.SSHCARawFileContent = []byte(encryptedTestSignerPrivateKey)

	defer os.Remove(passwdFile.Name()) // clean up
	state.Config.Base.Htpasswd_Filename = passwdFile.Name()

	// Make certgen Request
	certGenReq, err := createBasicAuthRequstWithKeyBody("POST", "/certgen/username", "username", "password")
	if err != nil {
		t.Fatal(err)
	}
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.certGenHandler)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, certGenReq)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}
	// Now we make the inject Request
	injectSecretRequest, err := http.NewRequest("POST", "/admin/inject", nil)
	if err != nil {
		t.Fatal(err)
	}
	var connectionState tls.ConnectionState
	injectSecretRequest.TLS = &connectionState

	r2 := httptest.NewRecorder()
	injectHandler := http.HandlerFunc(state.secretInjectorHandler)

	injectHandler.ServeHTTP(r2, injectSecretRequest)
	// Check the status code is what we expect.
	if status := r2.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusForbidden)
	}

	// now lets pretend that a tls connection with valid certs exists and try again
	var subjectCert x509.Certificate
	subjectCert.Subject.CommonName = "foo"
	peerCertList := []*x509.Certificate{&subjectCert}
	connectionState.VerifiedChains = append(connectionState.VerifiedChains, peerCertList)
	injectSecretRequest.TLS = &connectionState

	q := injectSecretRequest.URL.Query()
	q.Add("ssh_ca_password", "password")
	injectSecretRequest.URL.RawQuery = q.Encode()

	r3 := httptest.NewRecorder()
	injectHandler2 := http.HandlerFunc(state.secretInjectorHandler)
	injectHandler2.ServeHTTP(r3, injectSecretRequest)
	// Check the status code is what we expect.
	if status := r3.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	if state.Signer == nil {
		t.Errorf("The signer should now be loaded")
	}
	// Now we try to get a valid response
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr3 := httptest.NewRecorder()
	handler3 := http.HandlerFunc(state.certGenHandler)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler3.ServeHTTP(rr3, certGenReq)

	// Check the status code is what we expect.
	if status := rr3.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}
