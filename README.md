# google-auth-verify-id-token

Golang port of [OAuth2Client.prototype.verifyIdToken](https://github.com/google/google-auth-library-nodejs/blob/master/lib/auth/oauth2client.js) from [google-auth-library-nodejs](https://github.com/google/google-auth-library-nodejs)

Verify idtoken based on JWT flow without making http request to tokeninfo API.

## Deps

- golang.org/x/oauth2/jws

## See also

http://stackoverflow.com/questions/36716117/validating-google-sign-in-id-token-in-go#