package googleAuthIDTokenVerifier

import (
	"testing"
	"time"
)

func TestGetFederatedSignonCerts(t *testing.T) {
	certs, err := getFederatedSignonCerts(nil)
	if err != nil {
		t.Error(err)
		return
	}

	cacheAge := certs.Expiry.Sub(time.Now()).Seconds()
	t.Logf("cacheAge: %d", cacheAge)
	if cacheAge <= 7200 {
		t.Error("max-age not found")
	}

	key := certs.Keys["9e84f33bf244380eb676d35db27a49f86d7b2235"]
	if key == nil {
		t.Error("9e84f33bf244380eb676d35db27a49f86d7b2235 should exists")
	}
}

func TestGetFederatedSignonCertsCache(t *testing.T) {
	certs = &Certs{
		Expiry: time.Now(),
	}
	certs, err := getFederatedSignonCerts(nil) // trigger update
	if err != nil {
		t.Error(err)
		return
	}
	key := certs.Keys["9e84f33bf244380eb676d35db27a49f86d7b2235"]
	if key == nil {
		t.Error("9e84f33bf244380eb676d35db27a49f86d7b2235 should exists")
	}
}
