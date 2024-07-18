package decode

import "testing"

func TestParseRawParts(t *testing.T) {
	in := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	exp := B64Parts{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}
	obt, err := ParseRawParts(in)
	if err != nil {
		t.Fatalf("failed to parse jwt '%s'", in)
	}
	if exp != obt {
		t.Fatalf("failed to parse '%s', expected %v, obtained %v", in, exp, obt)
	}
}

func TestParseJwtInParts(t *testing.T) {
	in := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	exp := Parts{
		`{"alg":"HS256","typ":"JWT"}`,
		`{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	}
	obt, err := ParseJwtInParts(in)
	if err != nil {
		t.Fatalf("failed to parse jwt '%s'", in)
	}
	if exp != *obt {
		t.Fatalf("failed to parse and decode '%s', expected %v, obtained %v", in, exp, obt)
	}
}
