package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/Symantec/Dominator/lib/log/debuglogger"
	"github.com/Symantec/keymaster/lib/certgen"
	"github.com/Symantec/keymaster/lib/webapi/v0/proto"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"os"
	"os/user"
	"testing"
)

const rootCAPem = `-----BEGIN CERTIFICATE-----
MIIE1jCCAr4CAQowDQYJKoZIhvcNAQELBQAwMTELMAkGA1UEBhMCVVMxEDAOBgNV
BAoMB1Rlc3RPcmcxEDAOBgNVBAsMB1Rlc3QgQ0EwHhcNMTcwMTA1MTc0NzQ1WhcN
MzYxMjMxMTc0NzQ1WjAxMQswCQYDVQQGEwJVUzEQMA4GA1UECgwHVGVzdE9yZzEQ
MA4GA1UECwwHVGVzdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AK178Hyl2iJ8l4k/iHWgACtkLLa4n6sJo6DB8s1t98ILgU5ykT30jslWPH/QJvfL
/OAvgDcq2+ScwZThGFMxotBKnoufy88wAV/8SAwdy6rbAatW6v6K8+dgPEcka2jf
aqOby27+vrglQePQjjUMZoqr4qAizCUwCGZQUPhfSorBUcyWupKVZe8kDmD395yT
yRf3z5rJAMFzJmNOv/6ZOA2Scv14xZWTezBlr3E2zBCr0iYpYsqh5dG2ube9DYyX
0fXfrfaa8jstlu9jrYltxRmlCBAdoFB1N7eN6V/CsKc9nKc4dFkNDJng1Z4dpPYW
v+HzYI4UBsnkYFtpt5VV3M+Ys/FE1ARE4ah4R69FK+eBKCkpRUszbm/fjnt/QvDX
pCBcpa8vddgAgFKz9kvpO3lfA+jBb2euzX1lOL3ETooE0sEtFPK81P2M62BxsoIa
ztAWOQlLQotDtY156YaUoREXCjLkpiitEhpn9+nlMAPlA9X2iVQWIgpkAepbu+rU
ouODruaOoxc67GyTXUT7NIj3IE3PxPn5LBta+SOJ1DsUcC7aBG/x10/ifYLq/H4J
JxnHhac+S5aKxeCBTzT84JKltbYiqhhoGVaXYp6AwbOkqUMYyhEKelcvtdKc7fKF
+0DRAymVdGzV+nhwxGqwgarlXzZwsWkSj/A0+J7l2Ty9AgMBAAEwDQYJKoZIhvcN
AQELBQADggIBAKsYxpXFY4dyarnvMjAmX6EXcwqDfOJXgQdnX7QMzYlygMb+m2h1
Nuk4HTMlmQtkLba6JQd5NQw42RBYl1ef0PwwJoVlznht7Hec9wEopa5pyzyerSPT
nblh1TRKVffLQ1SyTO6yPgdn8rct5n2M0tW+nW7SZuWkzsc6swVEfJyTykXbMYHg
aSap7oMUr0MaffQjihzwk585fY8GvPeqdrer/k7d6MD05NWkqeXaMitI4hNWTyTu
7yjppKcGRVaNHmhk4867Jz6RZzxWbZBQe7tqaqmdqKLvz8/7j/VFjBTO2NebE0FV
LxKcpv6QklH0UWqzWBn8LDZRYz6D1PglGjgh8ERHOTKJW0BRdIlzljZwND2f5lSx
0HBSJYqTU38iBCHkxf8hYdiPI8Jw2CCt4l+hCwQhtIWgCrENSIa1sT9j3TPy+zwq
2GHf9xTpjV1pVEyuFPf1bllPUeOFXprJiq2J4rnE/fqyabO0uSX35ucdG+YGVyMa
BkwaEPvqvwremmh+xLYye6scQ+A/Wn9fN/8VN0W22t37O2VQNgsTANyIZwKZlxJc
fSkkhF5M7t/rWTtO0MXnCuIDJu3QJneRvOSBlvIabkVGEt9tZQCzK9wiJqsBkLSy
FCdYqoFk7gKsLkv51iMd+oItlEBuSEJSs1N+F5knShYfJdpHYDY+84ul
-----END CERTIFICATE-----`

const localhostCertPem = `-----BEGIN CERTIFICATE-----
MIIDvTCCAaUCBQLd4CbMMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYTAlVTMRAw
DgYDVQQKDAdUZXN0T3JnMRAwDgYDVQQLDAdUZXN0IENBMB4XDTE3MDEwNTE3NTQw
NVoXDTM2MTIzMTE3NTQwNVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3w9PziLdiuYkq4sxVEQkq0HIq6Ad/51o
k98AG87DqbG4hcPcbP/ItEHv4NdYZOtagY5twzb+sjcDC4plubQ9ewMKsGeBlDG4
xxkaMYJeqx8usmiT+fisiI6B+tM38ahxtYqcyCp3ou+WrSEuRb+70UXnztR8RT4R
ISkpq0wuj1Qcmxp9GkyA6aH4gwlj7EocqhIUCF2LxS8U0u2xvbCxHVSQFf4VxrrW
ZwoHaI8GWAZb/IAe9gxoau5rtJ90gpesO5AVx1VPX+WhpSCmVGPnJdknMXC6mjDJ
rMUW0KX8/dX7OdXAtSdDLzm6Yd4cI2DTnGVfckGIzsIYlGhBwxIUGwIDAQABMA0G
CSqGSIb3DQEBCwUAA4ICAQAlendYr/Xrh2h9tWRNB7kCS8OSaJqsaLP7nDWlwbj/
93QRB51qg2BHUy+tCzXAChq9HnaVcOLrDa0V3Amx5J6LauIBTnRBlHQGaw9Tu4Bo
UqMusHKM9/brNTDRUq8eafJhdfsXWs+cwKj9+Zh1UX0gc8yzgJSLCfkJgeuf62vP
tLAiJAxanxwT2hqtHnuVLu/UUmfx4n0IOALE8tARcLwZkKfmbsXiIY0ZIb/kwCuF
APYy4bmjRXfA9CKnHcfwOxYNqsAPad/MLme9bSBtOuY75VY3UDeno6Uz5PZL4163
8q+MedT6yinEtGaEllnpWMHa4NC0w+Klpk28fONEIxfqjCvlugRkIlCS3T9qfS9R
vhqwn1V+13JRYxLwMtVpXPdfQbBy7PG9VaQAyRsMrIGsG8esHx+OUMKP3hvh07gs
Lhmjn8SWaFpazldaNRcbOKazxHcwY+yL21VEL5CdA8GcjXEls3YaCuw54QBPJaoB
Yg4ybiaio7h8od1Nydf3mbQ9gmMruLpGHw7RKAGxBD6Ukt0uPAMKOgaL9H2YOSzB
SsYyE/ONrTbxpHZPQG1SszKuKUzGsPEwlMTwt8NHVTixKy/ttMA7NhN8KAYJrJQw
Z65R0mZFpYSL31jrfV4Q4mhFj6/Cr8rgmH++82FWfg88gf4lPk6/iDZtHvMMBUXy
Pg==
-----END CERTIFICATE-----`

const localhostKeyPem = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDfD0/OIt2K5iSr
izFURCSrQciroB3/nWiT3wAbzsOpsbiFw9xs/8i0Qe/g11hk61qBjm3DNv6yNwML
imW5tD17AwqwZ4GUMbjHGRoxgl6rHy6yaJP5+KyIjoH60zfxqHG1ipzIKnei75at
IS5Fv7vRRefO1HxFPhEhKSmrTC6PVBybGn0aTIDpofiDCWPsShyqEhQIXYvFLxTS
7bG9sLEdVJAV/hXGutZnCgdojwZYBlv8gB72DGhq7mu0n3SCl6w7kBXHVU9f5aGl
IKZUY+cl2ScxcLqaMMmsxRbQpfz91fs51cC1J0MvObph3hwjYNOcZV9yQYjOwhiU
aEHDEhQbAgMBAAECggEBALK97lFclvLK4O+lpm3D/S5OlKMSt3cxh6+WrtuZoCjH
BPoLrQKbJRVtEO+3IFoeTnQq0cHwu7/LXWFOEZ3x1KJSGaqqBqfeABdrAhZSRdIS
NrU4H/vbTUZQC9AWmWnIdPXokSHFBgFGxBMP16iEr9hOkCapFrvVtJxCA+YEMfsf
CKK9azdS/6aA4LxFKFuf7EwZz3uD5BqQXM/1vrAjmmATzE5yoJUsUPwJNwTlwTLs
53tOoZAIhYiWMXL1USXcKm3z8IJq8SgfgOUsK9X6IEEIga/IMwimPl966RlJyIsR
U4RzqG+cP5D2bC9n1M3aBUmUGcvWV7E3nVg+bbuNYIECgYEA76lfyMCbnnBzqagx
UpNR6PXn53RQicQktt+wFFexknf01ZmX+Tn3slSVtsms2xJRtUeNmljPKa7CIMWi
CaBLA2fsUjkPB0EQk6v8MzJeEJOpfFPWC+miKZhnV17rNkuuCwUdPFIz7g66/HU5
/W4gzrUkttw597cpOkOoiUrd16sCgYEA7kQzBa0ille35TlicqSQqeLQrTSga7b2
U0NjSwu0szCGw2LNV87H6Fhxw+MqIQM5VDTPb3bp9T0Uv2n0moENbGO5dD4ZGuNC
mA+AmKNeUBx81Jx4DumGxaU3eATkg6KlNKNccHtXF64k8blM9Y6q6ncCtr4UVz3H
ekSGNXx/hVECgYBf+o7XkPtBmntXqHoIPeOBzmlPMi/G3HxvmGml2/DLXar5mAda
0jI2gtVqXJ4TJeT/GmbFN2fPo6MvCLb57+3asVXdH+i62P3QhgH8ZuFw9hHcLp78
Kla9HcHVJbhBCFHtK+EndSxC3DdaP4A31FDjN3w6lzvHztx97vah9Q+e/QKBgQCk
8Y+EuXO9MmJ7DDvL84K2KO+fSFRZ3SIvR/JgDG1+svRIJIjU5bBcd4XiPst2aR3x
3lFP77lM7YkEbdxIbViWlX7YKvkENRlv3SOAB3CN8vqz0NIIOL/06Ug6DOEJA7ps
cz7WG3ySRxsKP+Y4BBjsEZFOYs4ACyOhz/g85L/+0QKBgQCjjTLjcSNg+fBZRXHC
YwzyBA/WXBPve5qo17Bt91knZ4m+xOVmRcswNG2U0eFrm+nNlk84Kj3TMRAv8Stx
GuCdIOQpn0IWClccTMjwc0AhJStSckNdSUQcsRl6LRnRHa3oCIs3hxnkiEHYch6e
dcxWzhBDbzeIV9SvcTwLx/ghQg==
-----END PRIVATE KEY-----`

const simpleValidConfigFile = `base:
    gen_cert_urls: "https://localhost:33443/"
`

const invalidConfigFileNoGenUrls = `base:
    `

const testUserPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI09fpMWTeYw7/EO/+FywS/sghNXdTeTWxX7K2N17owsQJX8s76LGVIdVeYrWg4QSmYlpf6EVSCpx/fbCazrsG7FJVTRhExzFbRT9asmvzS+viXSbSvnavhOz/paihyaMsVPKVv24vF6MOs8DgfwehcKCPjKoIPnlYXZaZcy05KOcZmsvYu2kNOP6sSjDFF+ru+T+DLp3DUGw+MPr45IuR7iDnhXhklqyUn0d7ou0rOHXz9GdHIzpr+DAoQGmTDkpbQEo067Rjfu406gYL8pVFD1F7asCjU39llQCcU/HGyPym5fa29Nubw0dzZZXGZUVFalxo02YMM7P9I6ZjeCsv cviecco@example.com`

func getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(localhostCertPem), []byte(localhostKeyPem))
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS11,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
	}, nil
}

const localHttpsTarget = "https://localhost:22443/"

var testAllowedCertBackends = []string{proto.AuthTypePassword, proto.AuthTypeU2F}

func handler(w http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{Name: "somename", Value: "somevalue"}
	http.SetCookie(w, &authCookie)
	switch r.URL.Path {
	case proto.LoginPath:
		loginResponse := proto.LoginResponse{Message: "success",
			CertAuthBackend: testAllowedCertBackends}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(loginResponse)

	default:
		fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	}
}

func init() {
	logger = debuglogger.New(stdlog.New(os.Stderr, "", stdlog.LstdFlags))
	tlsConfig, _ := getTLSconfig()
	//_, _ = tls.Listen("tcp", ":11443", config)
	srv := &http.Server{
		Addr:      ":22443",
		TLSConfig: tlsConfig,
	}
	http.HandleFunc("/", handler)
	go srv.ListenAndServeTLS("", "")
	//http.Serve(ln, nil)
}

func TestGenKeyPairSuccess(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "test_genKeyPair_")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	_, _, err = genKeyPair(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	fileBytes, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	_, err = certgen.GetSignerFromPEMBytes(fileBytes)
	if err != nil {
		t.Fatal(err)
	}
	//TODO: verify written signer matches our signer.
}

func TestGenKeyPairFailNoPerms(t *testing.T) {
	_, _, err := genKeyPair("/proc/something")
	if err == nil {
		t.Logf("Should have failed")
		t.Fatal(err)
	}
}

func TestGetUserHomeDirSuccess(t *testing.T) {
	usr, err := user.Current()
	if err != nil {
		t.Logf("cannot get current user info")
		t.Fatal(err)
	}
	homeDir, err := getUserHomeDir(usr)
	if err != nil {
		t.Fatal(err)
	}
	if len(homeDir) < 1 {
		t.Fatal("invalid homedir")

	}
}

func createTempFileWithStringContent(prefix string, content string) (f *os.File, err error) {
	f, err = ioutil.TempFile("", prefix)
	if err != nil {
		return nil, err
	}

	if _, err = f.Write([]byte(content)); err != nil {
		os.Remove(f.Name())
		return nil, err
	}
	return f, nil
}

func TestLoadVerifyConfigFileSuccess(t *testing.T) {
	tmpfile, err := createTempFileWithStringContent("test_LoadVerifyConfig", simpleValidConfigFile)
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = loadVerifyConfigFile(tmpfile.Name())

	if err != nil {
		t.Fatal(err)
	}
	// TODO: validate loaded file contents
}

func TestLoadVerifyConfigFileFailNotYAML(t *testing.T) {
	tmpfile, err := createTempFileWithStringContent("test_LoadVerifyConfigFail_", "Some random string")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = loadVerifyConfigFile(tmpfile.Name())
	if err == nil {
		t.Fatal("Should have failed not a YAML file")
	}
}

func TestLoadVerifyConfigFileFailNoGenCertUrls(t *testing.T) {
	tmpfile, err := createTempFileWithStringContent("test_LoadVerifyConfigFail_", invalidConfigFileNoGenUrls)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = loadVerifyConfigFile(tmpfile.Name())
	if err == nil {
		t.Fatal("Should have failed no genurls in config")
	}
}

func TestLoadVerifyConfigFileFailNoSuchFile(t *testing.T) {
	_, err := loadVerifyConfigFile("NonExistentFile")
	if err == nil {
		t.Fatal("Success on loading Nonexistent File!")
	}

}

func TestGetCertFromTargetUrlsSuccessOneURL(t *testing.T) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		t.Fatal(err)
	}
	skipu2f := true
	_, _, err = getCertFromTargetUrls(privateKey, "username", []byte("password"), []string{localHttpsTarget}, certPool, skipu2f) //(cert []byte, err error)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetCertFromTargetUrlsFailUntrustedCA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		t.Fatal(err)
	}
	skipu2f := true
	_, _, err = getCertFromTargetUrls(privateKey, "username", []byte("password"), []string{localHttpsTarget}, nil, skipu2f)
	if err == nil {
		t.Fatal("Should have failed to connect untrusted CA")
	}
}

func TestGetParseURLEnvVariable(t *testing.T) {
	testName := "TEST_ENV_KEYMASTER_11111"
	os.Setenv(testName, "http://localhost:12345")
	val, err := getParseURLEnvVariable(testName)
	if err != nil {
		t.Fatal(err)
	}
	if val == nil {
		t.Fatal("Should have found value")
	}

	//Not a URL
	/*
		os.Setenv(testName, "")
		if err == nil {
			t.Fatal("should have failed to parse")
		}
	*/

	//Unexistent
	val, err = getParseURLEnvVariable("Foobar")
	if val != nil {
		t.Fatal("SHOULD not have found anything ")
	}
	//

}

// ------------WARN-------- Next name copied from https://github.com/howeyc/gopass/blob/master/pass_test.go for using
//  gopass checks
func TestPipe(t *testing.T) {
	_, err := pipeToStdin("password\n")
	_, password, err := getUserInfoAndCreds()
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "password" {
		t.Fatal("password Does NOT match")
	}

}

// ------------WARN--------------
// THE next two functions are litierly copied from: https://github.com/howeyc/gopass/blob/master/pass_test.go
// pipeToStdin pipes the given string onto os.Stdin by replacing it with an
// os.Pipe.  The write end of the pipe is closed so that EOF is read after the
// final byte.
func pipeToStdin(s string) (int, error) {
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		fmt.Println("Error getting os pipes:", err)
		os.Exit(1)
	}
	os.Stdin = pipeReader
	w, err := pipeWriter.WriteString(s)
	pipeWriter.Close()
	return w, err
}

func pipeBytesToStdin(b []byte) (int, error) {
	return pipeToStdin(string(b))
}
