package main

import (
	"testing"
)

func TestGenKeyPairSuccess(t *testing.T) {
	_, err := genKeyPair("/tmp/foo")
	if err != nil {
		t.Fatal(err)
	}
}
