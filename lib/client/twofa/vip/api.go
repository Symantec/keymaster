// Package vip does two factor authentication with Symantec VIP
package vip

import (
	"net/http"

	"github.com/Symantec/Dominator/lib/log"
)

// DoVIPAuthenticate performs two factor authentication with Symantec VIP
func DoVIPAuthenticate(
	client *http.Client,
	authCookies []*http.Cookie,
	baseURL string,
	logger log.DebugLogger) error {
	return doVIPAuthenticate(client, authCookies, baseURL, logger)
}
