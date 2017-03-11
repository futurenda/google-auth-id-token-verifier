package googleAuth

import (
	"testing"
	"time"
)

func TestGetFederatedSignonCerts(t *testing.T) {
	certs, err := getFederatedSignonCerts()
	if err != nil {
		t.Error(err)
	}

	cacheAge := certs.Expiry.Sub(time.Now()).Seconds()
	t.Logf("cacheAge: %d", cacheAge)
	if cacheAge <= 7200 {
		t.Error("max-age not found")
	}
}
