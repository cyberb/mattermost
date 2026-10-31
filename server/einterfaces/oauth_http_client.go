package einterfaces

import "net/http"

type OAuthHTTPClient interface {
	HTTPClient() *http.Client
}
