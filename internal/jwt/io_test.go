package jwt

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestStdinJwtSource_GetJwtSource(t *testing.T) {
	// jwt value from jwt.io
	exp := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	source := &StdinJwtSource{value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}
	obt, err := source.GetJwt()
	if err != nil || obt != exp {
		t.Fatalf("error when extracting a jwt source: error obtained %v, exp %v obt %v", err, exp, obt)
	}
}

func TestFileJwtSource_GetJwt(t *testing.T) {
	// jwt value from jwt.io
	exp := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, exp)
	}))
	defer mockServer.Close()
	source := &UrlJwtSource{mockServer.URL}
	obt, err := source.GetJwt()
	if err != nil {
		t.Fatalf("failed test setup: failed to extract jwt from mock server due to follogin error: %v", err)
	}
	if exp != obt {
		t.Fatalf("error when extracting a jwt source: error obtained %v, exp %v obt %v", err, exp, obt)
	}
}

func TestUrlJwtSource_GetJwt(t *testing.T) {
	// jwt value from jwt.io
	exp := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	f, err := os.CreateTemp("", "test_file_jwt_source")
	if err != nil {
		t.Fatalf("failed test setup: failed to create a temporary file due to error: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err = f.WriteString(exp); err != nil {
		t.Fatalf("failed test setup: failed to write to temporary file due to error: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("failed test setup: failed to close temporary file due to error: %v", err)
	}
	source := &FileJwtSource{f.Name()}
	obt, err := source.GetJwt()
	if err != nil || exp != obt {
		t.Fatalf("error when extracting a jwt source: error obtained %v, exp %v obt %v", err, exp, obt)
	}
}
