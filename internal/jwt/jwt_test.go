package jwt

import (
	"testing"
)

func TestParseJwt(t *testing.T) {
	// from and reference decoding from jwt.io
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	exp := &Jwt{
		Head:      `{"alg":"HS256","typ":"JWT"}`,
		ClaimsSet: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		Signature: `SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
	}
	obt, err := ParseJwt(jwt)
	if err != nil {
		t.Fatalf("failed to decode jwt %v due to err: %v", jwt, err)
	}
	if obt.Head != exp.Head {
		t.Fatalf("failed to decode jwt %v due to mismatching header:\nexpected %v\nobtained %v", jwt, exp.Head, obt.Head)
	}
	if obt.ClaimsSet != exp.ClaimsSet {
		t.Fatalf("failed to decode jwt %v due to mismatching claim set:\nexpected %v\nobtained %v", jwt, exp.ClaimsSet, obt.ClaimsSet)
	}
	if obt.Signature != exp.Signature {
		t.Fatalf("failed to decode jwt %v due to mismatching signature:\nexpected %v\nobtained %v", jwt, exp.Signature, obt.Signature)
	}
}
