package googleAuth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"bytes"

	"golang.org/x/oauth2/jws"
)

func parseJWT(token string) (*jws.Header, *jws.ClaimSet, error) {
	s := strings.Split(token, ".")
	if len(s) != 3 {
		return nil, nil, errors.New("Invalid token received")
	}
	decodedHeader, err := base64.RawURLEncoding.DecodeString(s[0])
	if err != nil {
		return nil, nil, err
	}
	header := &jws.Header{}
	err = json.NewDecoder(bytes.NewBuffer(decodedHeader)).Decode(header)
	if err != nil {
		return nil, nil, err
	}
	claimSet, err := jws.Decode(token)
	if err != nil {
		return nil, nil, err
	}
	return header, claimSet, nil
}

// VerifySignedJWTWithCerts is golang port of OAuth2Client.prototype.verifySignedJwtWithCerts
func VerifySignedJWTWithCerts(token string, certs *Certs, requiredAudience string, issuers []string, maxExpiry time.Time) error {
	header, _, err := parseJWT(token)
	if err != nil {
		return err
	}
	key := certs.Keys[header.KeyID]
	err = jws.Verify(token, key)
	if err != nil {
		return err
	}
	return nil
}
