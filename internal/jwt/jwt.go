package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

const printIndentToken = "\t"

// Parts is a wrapper for a JWT. The head and claims in the struct are
// guaranteed to be strings representing valid json objects, while the
// signature is encoded in format base64 url encoding
type Parts struct {
	Head      string
	ClaimsSet string
	Signature string
}

// PrintOpts is container of all jwt print configurations
type PrintOpts struct {
	Indent   string
	KeyColor string
}

func (j *Parts) toDecoded() (*DecodedJwt, error) {
	var head, claims map[string]interface{}
	if err := json.Unmarshal([]byte(j.Head), &head); err != nil {
		return nil, fmt.Errorf("jwt header is not a json object: %w", err)
	}
	if err := json.Unmarshal([]byte(j.ClaimsSet), &claims); err != nil {
		return nil, fmt.Errorf("jwt claims are not a json object: %w", err)
	}
	return &DecodedJwt{head, claims, j.Signature, j}, nil
}

func (j *Parts) StringWithOpts(opts PrintOpts) string {
	var head, claims bytes.Buffer
	indentToken := opts.Indent
	err := json.Indent(&head, []byte(j.Head), "", indentToken)
	if err != nil {
		log.Panic(err)
	}
	err = json.Indent(&claims, []byte(j.ClaimsSet), "", indentToken)
	if err != nil {
		log.Panic(err)
	}
	prettyJwt := strings.Join([]string{head.String(), claims.String(), j.Signature}, "\n.\n")
	return colorize(prettyJwt, opts)
}

func (j *Parts) String() string {
	return j.StringWithOpts(PrintOpts{printIndentToken, printKeyColor})
}

// IsValid returns true if the given string is a valid jwt
// The function does NOT return why the string is not a valid. This task
// is delegated to the parser and in general parsing should be
// preferred to validation.
func IsValid(jwt string) bool {
	// could use a more concise implementation
	//https://datatracker.ietf.org/doc/html/rfc7519#section-7.2
	_, err := ParseJwtInParts(jwt)
	// TODO: compare to model and check
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

// ParseJwtInParts decode a string to jwt internal struct
// return error if the string cannot represent a JWT
func ParseJwtInParts(jwt string) (*Parts, error) {
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
	return &Parts{Head: header, ClaimsSet: claims, Signature: signatureB64}, nil
}
