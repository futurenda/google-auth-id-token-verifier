package googleAuthIDTokenVerifier

import (
	"strings"
	"testing"
	"time"
)

var (
	validTestToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjJmMmI1ZTZkOTZlMWQ0YzJjNmRhMjBhOGEwMGFjN2ZlNzdhYWNlOTAifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE0ODkwNzA3OTksImV4cCI6MTQ4OTA3NDM5OSwiYXVkIjoiNjg5MDAxMDQyMDcyLWUyajVkOWtsajdnNDRiNWd2cGdhNDlvMDY3a21rMTQyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTE3NzExOTcyMTg5MTM5NzkxNTU0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF6cCI6IjY4OTAwMTA0MjA3Mi1lMmo1ZDlrbGo3ZzQ0YjVndnBnYTQ5bzA2N2ttazE0Mi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsIm5vbmNlIjoiMTQ0NzUxMzI0OCIsImVtYWlsIjoiemVub29memVuZ0BnbWFpbC5jb20iLCJuYW1lIjoiWmVubyBaZW5nIiwicGljdHVyZSI6Imh0dHBzOi8vbGg2Lmdvb2dsZXVzZXJjb250ZW50LmNvbS8tSEZqaW55aTFjYWsvQUFBQUFBQUFBQUkvQUFBQUFBQUFBQkEvRE5WSG5qXzRpN28vczk2LWMvcGhvdG8uanBnIiwiZ2l2ZW5fbmFtZSI6Ilplbm8iLCJmYW1pbHlfbmFtZSI6IlplbmciLCJsb2NhbGUiOiJlbiJ9.P-dmXpGpLi7uKuaVQaIiu81PZGFThkVunmP8j7bxBhVrPvo1AZCOc0pJWboohdNY1zgbhfW9QUBAomfkivL_vWd6vWyDUzHQwtqRmH0wYUgby2dZ6elBvjH4iVYP-xLLHIfFCYfnPod7FFPGTt3yNUdXPreVAL69GyznFQ7eoMtP3dB0HqpU0_FzZvL22CGVs3p-AEjIsirlKh_ZNCKoizq12GpLZnae5YyrPl0mjY-D3sEoMNLTargclmu2B49j8BnlP-GpY5ltJuObsegfi05l_eobJU6ek-BVRq2932L3D_N4DP1uEJdnBbyN5AgVAnt3EQNJAaD_8CkqahCx0A"

	wrongSigToken = validTestToken + "A"
)

func TestParseJWT(t *testing.T) {
	header, claimSet, _ := parseJWT(validTestToken)
	if len(header.KeyID) == 0 {
		t.Errorf("Invalid kid")
	}
	if len(claimSet.Email) == 0 {
		t.Errorf("Invalid Email")
	}
}

func TestVerifier(t *testing.T) {
	v := Verifier{}
	err := v.VerifyIDToken(wrongSigToken, []string{})
	if err != ErrWrongSignature {
		t.Error("Expect ErrWrongSignature")
	}
	err = v.VerifyIDToken(validTestToken, []string{})
	if err != ErrTokenUsedTooLate {
		t.Error("Expect ErrTokenUsedTooLate")
	}

	_, claimSet, _ := parseJWT(validTestToken)

	nowFn = func() time.Time {
		return time.Unix(claimSet.Exp, 0)
	}
	err = v.VerifyIDToken(validTestToken, []string{})
	if !strings.Contains(err.Error(), "Wrong aud:") {
		t.Log(err.Error())
		t.Error("Expect wrong aud error")
	}

	t.Log(claimSet.Aud)

	err = v.VerifyIDToken(validTestToken, []string{
		claimSet.Aud,
	})
	if err != nil {
		t.Error(err)
	}

	nowFn = time.Now
}
