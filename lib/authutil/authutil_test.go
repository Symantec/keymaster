package authutil

import (
	"testing"
)

const testLdapsURL = `ldaps://ldap.example.com`
const testLdapURL = `ldap://ldap.example.com`
const testHttpURL = `http://www.example.com`

func TestParseLDAPURLSuccess(t *testing.T) {
	_, err := ParseLDAPURL(testLdapsURL)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseLDAPURLFail(t *testing.T) {

	_, err := ParseLDAPURL(testLdapURL)
	if err == nil {
		t.Logf("Failed to fail '%s'", testLdapURL)
		t.Fatal(err)
	}
	_, err = ParseLDAPURL(testHttpURL)
	if err == nil {
		t.Logf("Failed to fail '%s'", testHttpURL)
		t.Fatal(err)
	}
}
