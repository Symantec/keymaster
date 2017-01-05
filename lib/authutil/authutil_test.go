package authutil

import (
	"testing"
)

const testLdapsURL = `ldaps://ldap.example.com`
const testLdapURL = `ldap://ldap.example.com`
const testHttpURL = `http://www.example.com`

// This DB has user 'username' with password 'password'
const userdbContent = `username:$2y$05$D4qQmZbWYqfgtGtez2EGdOkcNne40EdEznOqMvZegQypT8Jdz42Jy`

func TestCheckHtpasswdUserPasswordSuccess(t *testing.T) {
	ok, err := CheckHtpasswdUserPassword("username", "password", []byte(userdbContent))
	if err != nil {
		t.Fatal(err)
	}
	if ok != true {
		t.Fatal("User considerd false")
	}
}

func TestCheckHtpasswdUserPassworFailBadPassword(t *testing.T) {
	ok, err := CheckHtpasswdUserPassword("username", "Incorrectpassword", []byte(userdbContent))
	if err != nil {
		t.Fatal(err)
	}
	if ok != false {
		t.Fatal("Logged in with bad password")
	}
}

func TestCheckHtpasswdUserPasswordUknownUsername(t *testing.T) {
	ok, err := CheckHtpasswdUserPassword("usernameUknown", "password", []byte(userdbContent))
	if err != nil {
		t.Fatal(err)
	}
	if ok != false {
		t.Fatal("Logged in with bad password")
	}
}

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
