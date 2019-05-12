package googleAuthIDTokenVerifier

import (
	"time"
	"net/http"
)

var (
	// MaxTokenLifetime is one day
	MaxTokenLifetime = time.Second * 86400

	// ClockSkew - five minutes
	ClockSkew = time.Minute * 5

	// Issuers is the allowed oauth token issuers
	Issuers = []string{
		"accounts.google.com",
		"https://accounts.google.com",
	}
)

type Verifier struct{}

func (v *Verifier) VerifyIDToken(idToken string, audience []string) error {
	certs, err := getFederatedSignonCerts(nil)
	if err != nil {
		return err
	}
	return VerifySignedJWTWithCerts(idToken, certs, audience, Issuers, MaxTokenLifetime)
}

func (v *Verifier) VerifyIDTokenWithCustomHttpClient(httpClient *http.Client, idToken string, audience []string) error {
	certs, err := getFederatedSignonCerts(&ClientOptions{client: httpClient})
	if err != nil {
		return err
	}
	return VerifySignedJWTWithCerts(idToken, certs, audience, Issuers, MaxTokenLifetime)
}
