package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

var headerExpectedKeys = [...]string{"alg", "type"}

type Jwt struct {
	Head      string
	ClaimsSet string
	Signature string
}

func (j *Jwt) ToString() string {
	return j.Head + "\n.\n" + j.ClaimsSet + "\n.\n" + j.Signature
}

// decode a jwt part (base 64 url encoded) to byte array
func decodeJwtPart(part string) ([]byte, error) {
	if len(part) == 0 {
		return make([]byte, 0), nil
	}
	size := base64.RawURLEncoding.DecodedLen(len(part))
	decoded := make([]byte, size)
	n, err := base64.RawURLEncoding.Decode([]byte(part), decoded)
	if err != nil {
		return nil, err
	}
	decoded = decoded[:n]
	return decoded, nil
}

// ParseJwt decode a string to jwt
// return error if the string is invalid
func ParseJwt(jwt string) (*Jwt, error) {
	numDots := strings.Count(jwt, ".")
	if numDots != 2 {
		return nil, fmt.Errorf("string %s is not a jwt: it does not contain 2 dots, but %v were found instead", jwt, numDots)
	}
	jwtParts := strings.Split(jwt, ".")

	rawHeader, err := decodeJwtPart(jwtParts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt header: not a valid base64 url endoded: %w", err)
	}
	header := string(rawHeader)
	if !json.Valid(rawHeader) {
		return nil, fmt.Errorf("decode JWT header is not a valid JSON: decoded header %s", header)
	}

	rawClaimSet, err := decodeJwtPart(jwtParts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt claim set: not a valid base64 url endoded: %w", err)
	}
	claimSet := string(rawClaimSet)
	if !json.Valid(rawClaimSet) {
		return nil, fmt.Errorf("decode JWT claim set is not a valid JSON: decoded claims set %s", string(rawClaimSet))
	}

	rawSignature := jwtParts[2] // might be empty is sign is none

	return &Jwt{Head: header, ClaimsSet: claimSet, Signature: rawSignature}, nil
}
