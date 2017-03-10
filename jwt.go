package googleAuth

import (
	"time"

	"golang.org/x/oauth2/jws"
)

// VerifySignedJWTWithCerts is golang port of OAuth2Client.prototype.verifySignedJwtWithCerts
func VerifySignedJWTWithCerts(token string, certs *Certs, requiredAudience string, issuers []string, maxExpiry time.Time) error {
	claimSet, err := jws.Decode(token)
	if err != nil {
		return err
	}
}
