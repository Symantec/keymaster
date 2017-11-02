package main

import (
	"crypto"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// This actually gets the SSH key fingerprint
func getKeyFingerprint(key crypto.PublicKey) (string, error) {
	sshPublicKey, err := ssh.NewPublicKey(key)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(sshPublicKey.Marshal())
	fp := fmt.Sprintf("%x", h.Sum(nil))
	return fp, nil
}
