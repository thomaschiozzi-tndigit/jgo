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
const printKeyColor = "\033[36m"
const colorNone = "\033[0m"

// Jwt is a wrapper for a JWT. The head and claims in the struct are
// guaranteed to be valid json strings, while the string is encoded in
// format base64 url encoding
type Jwt struct {
	Head      string
	ClaimsSet string
	Signature string
}

// PrintOpts is container of all jwt print configurations
type PrintOpts struct {
	Indent   string
	KeyColor string
}

func (j *Jwt) StringWithOpts(opts PrintOpts) string {
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

func (j *Jwt) String() string {
	return j.StringWithOpts(PrintOpts{printIndentToken, printKeyColor})
}

// colorize will print a colored decoded jwt
// currently does not work properly if there is no indent
func colorize(s string, opts PrintOpts) string {
	if len(s) == 0 {
		return ""
	}
	if opts.KeyColor == "" {
		return s
	}
	indentWindows := len(opts.Indent)
	var b strings.Builder
	var isColored bool
	var cc string
	isColored = false
	for i, c := range s {
		cc = string(c)
		if cc != `"` {
			b.WriteString(cc)
			continue
		}
		if isColored {
			b.WriteString(cc)
			b.WriteString(colorNone)
			isColored = false
		} else {
			if s[(i-indentWindows):i] == opts.Indent {
				b.WriteString(opts.KeyColor)
			}
			b.WriteString(cc)
			isColored = true
		}
	}
	return b.String()
}

// IsValid returns true if the given string is a valid jwt
// The function does NOT return why the string is not a valid. This task
// is delegated to the parser and in general parsing should be
// preferred to validation.
func IsValid(jwt string) bool {
	// could use a more concise implementation
	//https://datatracker.ietf.org/doc/html/rfc7519#section-7.2
	_, err := ParseJwt(jwt)
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
