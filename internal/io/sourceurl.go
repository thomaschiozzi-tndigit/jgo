package io

import (
	"fmt"
	"io"
	"net/http"
)

// UrlJwtSource finds a JWT from an HTTP GET request
type UrlJwtSource struct {
	url string
}

func NewUrlJwtSource(url string) *UrlJwtSource {
	return &UrlJwtSource{url}
}

func (u *UrlJwtSource) GetJwt() (string, error) {
	r, err := http.Get(u.url)
	if err != nil {
		return "", err
	}
	if r.StatusCode != http.StatusOK {
		return "", fmt.Errorf("remote request response was not 200, instead: %v", r.StatusCode)
	}
	jwt, err := io.ReadAll(r.Body)
	return string(jwt), nil
}
