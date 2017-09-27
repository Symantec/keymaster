package util

import (
	"github.com/Symantec/Dominator/lib/log/testlogger"
	"github.com/Symantec/keymaster/lib/certgen"
	"io/ioutil"
	"os"
	"os/user"
	"testing"
)

func TestGenKeyPairSuccess(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "test_genKeyPair_")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	_, _, err = GenKeyPair(tmpfile.Name(), "test", testlogger.New(t))
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
	_, _, err := GenKeyPair("/proc/something", "test", testlogger.New(t))
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
	homeDir, err := GetUserHomeDir(usr)
	if err != nil {
		t.Fatal(err)
	}
	if len(homeDir) < 1 {
		t.Fatal("invalid homedir")

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
