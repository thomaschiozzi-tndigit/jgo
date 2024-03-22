package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

var headerExpectedKeys = [...]string{"alg", "type"}

// Jwt is a wrapper for a JWT. The head and claims in the struct are
// guaranteed to be valid json strings, while the string is encoded in
// format base64 url encoding
type Jwt struct {
	Head      string
	ClaimsSet string
	Signature string
}

func (j *Jwt) String() string {
	var head, claims bytes.Buffer
	separator := "    "
	err := json.Indent(&head, []byte(j.Head), "", separator)
	if err != nil {
		log.Panic(err)
	}
	err = json.Indent(&claims, []byte(j.ClaimsSet), "", separator)
	if err != nil {
		log.Panic(err)
	}
	return strings.Join([]string{head.String(), claims.String(), j.Signature}, "\n.\n")
}

// IsValid returns true if the given string is a valid jwt
// The function does NOT return why the string is not a valid. This task
// is delegated to the parser and in general parsing should be
// preferred to validation.
func IsValid(jwt string) bool {
	_, err := ParseJwt(jwt)
	if err != nil {
		return false
	}
	return true
}

// decode a jwt part (base 64 url encoded) to a valid JSON string
// Returns error is the decoding fails or if the result is not a valid JSON string
func decodeJwtPart(part string) (string, error) {
	if len(part) == 0 {
		return "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return "", err
	}
	// TODO: consider moving this to IsValid() method
	if !json.Valid(decoded) {
		return "", fmt.Errorf("decoded JWT part is not a valid JSON string")
	}
	return string(decoded), nil
}

func splitJwt(jwt string) (string, string, string, error) {
	numDots := strings.Count(jwt, ".")
	if numDots != 2 {
		return "", "", "", fmt.Errorf("string %s is not a jwt: it does not contain 2 dots, but %v were found instead", jwt, numDots)
	}
	jwtParts := strings.Split(jwt, ".")
	return jwtParts[0], jwtParts[1], jwtParts[2], nil
}

// ParseJwt decode a string to jwt internal struct
// return error if the string cannot represent a JWT
func ParseJwt(jwt string) (*Jwt, error) {
	headB64, claimsB64, signatureB64, err := splitJwt(jwt)
	if err != nil {
		return nil, err
	}
	header, err := decodeJwtPart(headB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt header %s: %w", headB64, err)
	}
	claims, err := decodeJwtPart(claimsB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt claim set %s: %w", claimsB64, err)
	}
	// TODO: check that signature is b64 url encoded
	return &Jwt{Head: header, ClaimsSet: claims, Signature: signatureB64}, nil
}
