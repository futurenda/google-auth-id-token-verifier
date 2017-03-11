package googleAuthIDTokenVerifier

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

type Certs struct {
	Keys   map[string]*rsa.PublicKey
	Expiry time.Time
}

var (
	certs *Certs

	// Google Sign on certificates.
	googleOAuth2FederatedSignonCertsURL = "https://www.googleapis.com/oauth2/v3/certs"
)

type key struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"Kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type response struct {
	Keys []*key `json:"keys"`
}

func getFederatedSignonCerts() (*Certs, error) {
	if certs != nil {
		if time.Now().Before(certs.Expiry) {
			return certs, nil
		}
	}
	resp, err := http.Get(googleOAuth2FederatedSignonCertsURL)
	if err != nil {
		return nil, err
	}
	cacheControl := resp.Header.Get("cache-control")
	cacheAge := int64(7200) // Set default cacheAge to 2 hours
	if len(cacheControl) > 0 {
		re := regexp.MustCompile("max-age=([0-9]*)")
		match := re.FindAllStringSubmatch(cacheControl, -1)
		if len(match) > 0 {
			if len(match[0]) == 2 {
				maxAge := match[0][1]
				maxAgeInt, err := strconv.ParseInt(maxAge, 10, 64)
				if err != nil {
					return nil, err
				}
				cacheAge = maxAgeInt
			}
		}
	}

	res := &response{}
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	keys := map[string]*rsa.PublicKey{}
	for _, key := range res.Keys {
		if key.Use == "sig" && key.Kty == "RSA" {
			n, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, err
			}
			e, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, err
			}
			ei := big.NewInt(0).SetBytes(e).Int64()
			if err != nil {
				return nil, err
			}
			keys[key.Kid] = &rsa.PublicKey{
				N: big.NewInt(0).SetBytes(n),
				E: int(ei),
			}
		}
	}
	certs = &Certs{
		Keys:   keys,
		Expiry: time.Now().Add(time.Second * time.Duration(cacheAge)),
	}

	return certs, nil
}
