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
func VerifySignedJWTWithCerts(token string, certs *Certs, requiredAudience string, issuers []string, maxExpiry time.Duration) error {
	header, claimSet, err := parseJWT(token)
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
	if claimSet.Iat < 1 {
		return fmt.Errorf("jwt: no issue time in token: %s", token)
	}
	if claimSet.Exp < 1 {
		return fmt.Errorf("jwt: no expiration time in token: %s", token)
	}
	now := time.Now()
	if claimSet.Exp > now.Unix()+int64(maxExpiry.Seconds()) {
		return fmt.Errorf("jwt: expiration time too far in future: %s", token)
	}

	earliest := claimSet.Iat - int64(ClockSkew.Seconds())
	latest := claimSet.Iat + int64(ClockSkew.Seconds())

	if now.Unix() < earliest {
		return fmt.Errorf("jwt: token used too early, %d < %d: %s", now.Unix(), earliest, token)
	}

	if now.Unix() > latest {
		return fmt.Errorf("jwt: token used too late, %d > %d: %s", now.Unix(), latest, token)
	}
	return nil
}
