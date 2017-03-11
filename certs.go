package googleAuth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
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
)

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

	keys := map[string]*rsa.PublicKey{}
	m := map[string]string{}
	err = json.NewDecoder(resp.Body).Decode(&m)
	if err != nil {
		return nil, err
	}

	for k, v := range m {
		fmt.Printf("k: %s, v: %s", k, v)
		key, err := x509.ParsePKIXPublicKey([]byte(v))
		if err != nil {
			return nil, err
		}
		keys[k] = key.(*rsa.PublicKey)
	}
	certs = &Certs{
		Keys:   keys,
		Expiry: time.Now().Add(time.Second * time.Duration(cacheAge)),
	}

	return nil, nil
}
