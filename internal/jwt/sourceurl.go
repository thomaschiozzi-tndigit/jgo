package jwt

import (
	"io"
	"net/http"
)

// UrlJwtSource finds a JWT from an HTTP GET request
type UrlJwtSource struct {
	url string
}

func (u *UrlJwtSource) GetJwt() (string, error) {
	r, err := http.Get(u.url)
	if err != nil {
		return "", err
	}
	// TODO: parse the get body to obtain jwt
	jwt, err := io.ReadAll(r.Body)
	return string(jwt), nil
}
