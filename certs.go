package googleAuth

import (
	"crypto/rsa"
	"net/http"
	"time"
)

type Certs struct {
	Keys   map[string]*rsa.PublicKey
	Expiry time.Time
}

func getFederatedSignonCerts() error {
	resp, err := http.Get(googleOAuth2FederatedSignonCertsURL)
	resp.Header.Get("")
	return nil
}
