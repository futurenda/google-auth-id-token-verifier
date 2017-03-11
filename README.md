# google-auth-id-token-verifier

Golang port of [OAuth2Client.prototype.verifyIdToken](https://github.com/google/google-auth-library-nodejs/blob/master/lib/auth/oauth2client.js) from [google-auth-library-nodejs](https://github.com/google/google-auth-library-nodejs)

Verify idtoken based on JWT flow without making http request to tokeninfo API.

## Usage

```go

import (
    "github.com/futurenda/google-auth-id-token-verifier"
)

v := googleAuthIDTokenVerifier.Verifier{}
aud := "xxxxxx-yyyyyyy.apps.googleusercontent.com"
err := v.VerifyIDToken(TOKEN, []string{
    aud,
})
if err == nil {
    claimSet, err := googleAuthIDTokenVerifier.Decode(TOKEN)
    // claimSet.Iss,claimSet.Email ... (See claimset.go)
}
```

## Deps

- golang.org/x/oauth2/jws

## See also

http://stackoverflow.com/questions/36716117/validating-google-sign-in-id-token-in-go#