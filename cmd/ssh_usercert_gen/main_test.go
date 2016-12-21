package main

import (
	"bytes"
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

const testUserPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI09fpMWTeYw7/EO/+FywS/sghNXdTeTWxX7K2N17owsQJX8s76LGVIdVeYrWg4QSmYlpf6EVSCpx/fbCazrsG7FJVTRhExzFbRT9asmvzS+viXSbSvnavhOz/paihyaMsVPKVv24vF6MOs8DgfwehcKCPjKoIPnlYXZaZcy05KOcZmsvYu2kNOP6sSjDFF+ru+T+DLp3DUGw+MPr45IuR7iDnhXhklqyUn0d7ou0rOHXz9GdHIzpr+DAoQGmTDkpbQEo067Rjfu406gYL8pVFD1F7asCjU39llQCcU/HGyPym5fa29Nubw0dzZZXGZUVFalxo02YMM7P9I6ZjeCsv camilo_viecco1@mon-sre-dev.ash2.symcpe.net`

// This DB has user 'username' with password 'password'
const userdbContent = `username:$2y$05$D4qQmZbWYqfgtGtez2EGdOkcNne40EdEznOqMvZegQypT8Jdz42Jy`

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
	// make tmpfile with db content
	tmpfile, err := ioutil.TempFile("", "userdb_test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write([]byte(userdbContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}
	state.Config.Base.Htpasswd_Filename = tmpfile.Name()

	//create attachment....
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	//
	fileWriter, err := bodyWriter.CreateFormFile("pubkeyfile", "somefilename.pub")
	if err != nil {
		fmt.Println("error writing to buffer")
		t.Fatal(err)
	}
	fh := strings.NewReader(testUserPublicKey)

	//iocopy
	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		t.Fatal(err)
	}

	//log.Printf("%v", bodyBuf)
	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/certgen/username", bodyBuf)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("username", "password")
	req.Header.Set("Content-Type", contentType)

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
