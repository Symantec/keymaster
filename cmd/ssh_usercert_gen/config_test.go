package main

import (
	"bufio"
	//"encoding/json"
	//"fmt"
	//"golang.org/x/net/context"
	//"golang.org/x/oauth2"
	"io/ioutil"
	//"log"
	//"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	//"time"
)

func TestGenerateNewConfigInternal(t *testing.T) {
	t.Logf("hello")
	dir, err := ioutil.TempDir("", "config_testing")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	configFilename := filepath.Join(dir, "config-test.yml")

	readerContent := dir + "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
	baseReader := strings.NewReader(readerContent)
	reader := bufio.NewReader(baseReader)
	err = generateNewConfigInternal(reader, configFilename, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// AND not try to load
	_, err = loadVerifyConfigFile(configFilename)
	if err != nil {
		t.Fatal(err)
	}

	//Need to decrypt file

}
