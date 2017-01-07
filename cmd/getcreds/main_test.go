package main

import (
	"io/ioutil"
	"os"
	"os/user"
	"testing"
)

func TestGenKeyPairSuccess(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "example")
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
