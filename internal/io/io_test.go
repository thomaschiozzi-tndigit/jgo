package io

import "testing"

func TestAutoSource(t *testing.T) {
	type testcase struct {
		v   string
		exp SourceType
		obt SourceType
	}
	cases := []testcase{
		{"eyJjdWwiOiJiZWwiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImJkMGRkZTlkODQ4Y2EwNWI4ZjQ4N2E0NGQ0NzEzMTY2In0.e30.r6XXFX4TX6YOOytCTNz0HfreSMU6XRPpZdMRqVXX-DqUWaFWTtv9pBAF3NHYxccj_t-Ru2JXlzPjFG6wpIXDig", SourceStdin, -1},
		{"http://my-rp.example/.well-known/openid-federation", SourceUrl, -1},
		{"https://my-rp.example/fetch?sub=http://my-subjec.example", SourceUrl, -1},
		{"encoded_file.jwt", SourcePath, -1},
		{"encoded_file.b64.txt", SourcePath, -1},
		{"C:/absolute/path/to/file/encoded_file.jwt", SourcePath, -1},
		{"relative\\path\\to\\file\\encoded_file.b64.txt", SourcePath, -1},
	}

	for i, tc := range cases {
		tc.obt = autoDetectsSourceTypeFromValue(tc.v)
		if tc.exp != tc.obt {
			t.Fatalf("failed case %v with value '%s': exp %v: obt %v", i, tc.v, tc.exp, tc.obt)
		}
	}
}
