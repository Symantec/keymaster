package util

import (
	"bytes"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strings"
)

func CreateSimpleDataBodyRequest(method string, urlStr string, filebytes []byte, contentType string) (*http.Request, error) {
	bodyBuf := bytes.NewBuffer(filebytes)
	req, err := http.NewRequest(method, urlStr, bodyBuf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return req, nil
}

// This is now copy-paste from the server test side... probably make public and reuse.
func CreateFormDataBodyRequest(method, urlStr, filedata string, fieldname string, filename string) (*http.Request, error) {
	//create attachment....
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	//
	fileWriter, err := bodyWriter.CreateFormFile(fieldname, filename)
	if err != nil {
		log.Println("error writing to buffer")
		return nil, err
	}
	// When using a file this used to be: fh, err := os.Open(pubKeyFilename)
	fh := strings.NewReader(filedata)

	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		return nil, err
	}

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	req, err := http.NewRequest(method, urlStr, bodyBuf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	return req, nil
}
