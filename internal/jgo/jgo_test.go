package jgo

import (
	"reflect"
	"testing"
)

func TestParseJgo(t *testing.T) {
	in := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	exp := Jgo{
		map[string]interface{}{
			"alg": "HS256",
			"typ": "JWT",
		},
		map[string]interface{}{
			"sub":  "1234567890",
			"name": "John Doe",
			"iat":  1516239022,
		},
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	}
	obt, err := ParseJgo(in, NoOpts)
	if err != nil {
		t.Fatalf("failed to parse, decode and unmarshal jwt '%s', cause %v", in, err)
	}
	if reflect.DeepEqual(exp, *obt) {
		t.Fatalf("failed to parse, decode and unmarshal '%s', expected %v, obtained %v", in, exp, obt)
	}

}
