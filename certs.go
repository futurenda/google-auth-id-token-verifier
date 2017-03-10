package googleAuth

import (
	"net/http"
	"time"
)

type Certs struct {
	Certs  map[string]string
	Expiry time.Time
}

func getFederatedSignonCerts() error {
	resp, err := http.Get(googleOAuth2FederatedSignonCertsURL)
	return nil
}
