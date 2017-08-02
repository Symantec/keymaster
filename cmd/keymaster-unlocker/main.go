package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/howeyc/gopass"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

var (
	Version    = "No version provided"
	certFile   = flag.String("cert", "client.pem", "A PEM eoncoded certificate file.")
	keyFile    = flag.String("key", "key.pem", "A PEM encoded private key file.")
	targetHost = flag.String("keymasterHostname", "", "The hostname/port for keymaster")
	targetPort = flag.Int("keymasterPort", 6920, "The port for keymaster control port")
)

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
}

func main() {
	flag.Parse()

	if len(*targetHost) < 1 {
		log.Fatal("keymasterHostname paramteter  is required")
	}

	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Password for unlocking %s: ", *targetHost)
	password, err := gopass.GetPasswd()
	if err != nil {
		log.Fatal(err)
		// Handle gopass.ErrInterrupted or getch() read error
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Do GET something
	resp, err := client.PostForm("https://"+*targetHost+":"+strconv.Itoa(*targetPort)+"/admin/inject",
		url.Values{"ssh_ca_password": {string(password[:])}})
	//resp, err := client.Get("https://goldportugal.local:8443")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(data))
}
