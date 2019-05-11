package main

import (
	"os"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	testSecret := "superSecret"
	cipherTexts, err := state.encryptWithPublicKeys([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	plainTextBytes, err := state.decryptWithPublicKeys(cipherTexts)

	if err != nil {
		t.Fatal(err)
	}
	if string(plainTextBytes) != testSecret {
		t.Fatal("values do not match")
	}
}
