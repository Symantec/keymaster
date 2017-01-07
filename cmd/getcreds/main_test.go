package main

import (
	"io/ioutil"
	"os"
	"os/user"
	"testing"
)

const simpleValidConfigFile = `base:
    gen_cert_urls: "https://localhost:33443/certgen/"
`

func TestGenKeyPairSuccess(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "test_genKeyPair_")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	_, err = genKeyPair(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	//TODO: verify genKeyPair File content
}

func TestGenKeyPairFailNoPerms(t *testing.T) {
	_, err := genKeyPair("/proc/something")
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

func TestLoadVerifyConfigFileSuccess(t *testing.T) {
	//content := []byte("temporary file's content")
	tmpfile, err := ioutil.TempFile("", "test_LoadVerifyConfig")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write([]byte(simpleValidConfigFile)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = loadVerifyConfigFile(tmpfile.Name())

	if err != nil {
		t.Fatal(err)
	}
	// TODO: validate loaded file contents
}

func TestLoadVerifyConfigFileFailNoSuchFile(t *testing.T) {
	_, err := loadVerifyConfigFile("NonExistentFile")
	if err == nil {
		t.Fatal("Success on loading Nonexistent File!")
	}

}
