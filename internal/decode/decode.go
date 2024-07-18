package decode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type B64Parts struct {
	B64Header    string
	B64Claims    string
	B64Signature string
}

func (b64parts *B64Parts) IsZero() bool {
	return b64parts.B64Header == "" && b64parts.B64Claims == "" && b64parts.B64Signature == ""
}

func (b64parts *B64Parts) ToDecodedParts() (Parts, error) {
	if b64parts.IsZero() {
		return Parts{}, nil
	}
	header, err := decodeJwtPart(b64parts.B64Header)
	if err != nil {
		return Parts{}, fmt.Errorf("failed to decode jwt header %s: %w", b64parts.B64Header, err)
	}
	claims, err := decodeJwtPart(b64parts.B64Claims)
	if err != nil {
		return Parts{}, fmt.Errorf("failed to decode jwt claim set %s: %w", b64parts.B64Claims, err)
	}
	return Parts{Head: header, ClaimsSet: claims, Signature: b64parts.B64Signature}, nil
}

func ParseRawParts(jwt string) (B64Parts, error) {
	if jwt == "" {
		return B64Parts{}, nil
	}
	numDots := strings.Count(jwt, ".")
	if numDots != 2 {
		return B64Parts{}, fmt.Errorf("string %s is not a jwt: it does not contain 2 dots, but %v were found instead", jwt, numDots)
	}
	parts := strings.Split(jwt, ".")
	headB64 := parts[0]
	claimsB64 := parts[1]
	signatureB64 := parts[2]
	return B64Parts{headB64, claimsB64, signatureB64}, nil
}

// Parts is a wrapper for a JWT. The head and claims in the struct are
// guaranteed to be strings representing valid json objects, while the
// signature is encoded in format base64 url encoding
type Parts struct {
	Head      string
	ClaimsSet string
	Signature string
}

//func (j *Parts) toDecoded() (*jwt.UnmarshalledJgo, error) {
//	var head, claims map[string]interface{}
//	if err := json.Unmarshal([]byte(j.Head), &head); err != nil {
//		return nil, fmt.Errorf("jwt header is not a json object: %w", err)
//	}
//	if err := json.Unmarshal([]byte(j.ClaimsSet), &claims); err != nil {
//		return nil, fmt.Errorf("jwt claims are not a json object: %w", err)
//	}
//	return &jwt.UnmarshalledJgo{head, claims, j.Signature, j}, nil
//}

//
//func (j *Parts) StringWithOpts(opts io.PrintOpts) string {
//	var head, claims bytes.Buffer
//	indentToken := opts.Indent
//	err := json.Indent(&head, []byte(j.Head), "", indentToken)
//	if err != nil {
//		log.Panic(err)
//	}
//	err = json.Indent(&claims, []byte(j.ClaimsSet), "", indentToken)
//	if err != nil {
//		log.Panic(err)
//	}
//	prettyJwt := strings.Join([]string{head.String(), claims.String(), j.Signature}, "\n.\n")
//	return jwt.colorize(prettyJwt, opts)
//}
//
//func (j *Parts) String() string {
//	return j.StringWithOpts(io.PrintOpts{jwt.printIndentToken, jwt.printKeyColor})
//}

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
		return "", fmt.Errorf("decoded jwt part is not a valid json string")
	}
	return string(decoded), nil
}

// ParseJwtInParts decode a string to jwt internal struct
// return error if the string cannot represent a JWT
func ParseJwtInParts(jwt string) (*Parts, error) {
	raws, err := ParseRawParts(jwt)
	if err != nil {
		return nil, err
	}
	parts, err := raws.ToDecodedParts()
	return &parts, err
}
