package googleAuth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"bytes"

	"fmt"

	"golang.org/x/oauth2/jws"
)

func parseJWT(token string) (*jws.Header, *ClaimSet, error) {
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
	claimSet, err := Decode(token)
	if err != nil {
		return nil, nil, err
	}
	return header, claimSet, nil
}

// Decode returns ClaimSet
func Decode(token string) (*ClaimSet, error) {
	s := strings.Split(token, ".")
	if len(s) != 3 {
		return nil, errors.New("Invalid token received")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	c := &ClaimSet{}
	err = json.NewDecoder(bytes.NewBuffer(decoded)).Decode(c)
	return c, err
}

// VerifySignedJWTWithCerts is golang port of OAuth2Client.prototype.verifySignedJwtWithCerts
func VerifySignedJWTWithCerts(token string, certs *Certs, requiredAudience string, issuers []string, maxExpiry time.Time) error {
	header, _, err := parseJWT(token)
	if err != nil {
		return err
	}
	key := certs.Keys[header.KeyID]
	if key == nil {
		return fmt.Errorf("jwt: no pem found for kid: %s, ", header.KeyID)
	}
	err = jws.Verify(token, key)
	if err != nil {
		return fmt.Errorf("jwt: invalid token signature, %s", err.Error())
	}
	return nil
}
