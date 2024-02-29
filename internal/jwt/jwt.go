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
	//return j.Head + "\n.\n" + j.ClaimsSet + "\n.\n" + j.Signature
}

func (j *Jwt) IsValid() bool {
	// TODO
	return false
}

func (j *Jwt) CheckSignature() string {
	// TODO
	return "TODO"
}

// decode a jwt part (base 64 url encoded) to byte array
func decodeJwtPart(part string) ([]byte, error) {
	if len(part) == 0 {
		return make([]byte, 0), nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func splitJwt(jwt string) (string, string, string, error) {
	// TODO: refactor and review
	return "", "", "", nil
}

// ParseJwt decode a string to jwt internal struct
// return error if the string is invalid
func ParseJwt(jwt string) (*Jwt, error) {
	// TODO: use splitJwt
	numDots := strings.Count(jwt, ".")
	if numDots != 2 {
		return nil, fmt.Errorf("string %s is not a jwt: it does not contain 2 dots, but %v were found instead", jwt, numDots)
	}

	jwtParts := strings.Split(jwt, ".")

	rawHeader, err := decodeJwtPart(jwtParts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt header %s: not a valid base64 url encoded string: %w", jwtParts[0], err)
	}
	header := string(rawHeader)
	if !json.Valid(rawHeader) {
		return nil, fmt.Errorf("decode JWT header is not a valid JSON: decoded header %s", header)
	}

	rawClaimSet, err := decodeJwtPart(jwtParts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt claim set %s: not a valid base64 url encoded string: %w", jwtParts[1], err)
	}
	claimSet := string(rawClaimSet)
	if !json.Valid(rawClaimSet) {
		return nil, fmt.Errorf("decode JWT claim set is not a valid JSON: decoded claims set %s", string(rawClaimSet))
	}

	rawSignature := jwtParts[2] // might be empty if sign is none

	return &Jwt{Head: header, ClaimsSet: claimSet, Signature: rawSignature}, nil
}
