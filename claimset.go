package googleAuthIDTokenVerifier

import (
	"golang.org/x/oauth2/jws"
)

type ClaimSet struct {
	jws.ClaimSet
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
	// Hd is the hosted domain, present if the user is in a Gsuite domain.
	Hd  string `json:"hd,omitempty"`
}
