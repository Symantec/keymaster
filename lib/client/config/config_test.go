package config

import (
	"io/ioutil"
	"os"
	"testing"
)

const simpleValidConfigFile = `base:
    gen_cert_urls: "https://localhost:33443/"
`

const invalidConfigFileNoGenUrls = `base:
	    `

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
