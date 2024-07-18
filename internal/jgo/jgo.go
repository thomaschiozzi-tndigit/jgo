package jgo

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thomaschiozzi-tndigit/jgo/internal/decode"
)

// Jgo is an internal representation of a Jwt as Json. The Jwt parts are
// mapped to appropriate key with unique namespace.
type Jgo struct {
	Head      map[string]interface{} `json:"_jgo.jwt.head,omitempty"`
	Clams     map[string]interface{} `json:"_jgo.jwt.claims,omitempty"`
	Signature string                 `json:"_jgo.jwt.signature,omitempty"`
}

type UnmarshalOpts int

const (
	NoOpts UnmarshalOpts = iota
	Recursive
	ConvertDate
)

func ParseJgo(jwt string, opts ...UnmarshalOpts) (*Jgo, error) {
	parts, err := decode.ParseJwtInParts(jwt)
	if err != nil {
		return nil, err
	}
	head, err := unmarshallPart([]byte(parts.Head), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall jwt header: %w", err)
	}
	claims, err := unmarshallPart([]byte(parts.ClaimsSet), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall jwt header: %w", err)
	}
	return &Jgo{Head: head, Clams: claims, Signature: parts.Signature}, nil
}

func unmarshallPart(part []byte, opts ...UnmarshalOpts) (map[string]interface{}, error) {
	if !json.Valid(part) {
		return nil, errors.New("part is not a valid json")
	}
	var v interface{}
	if err := json.Unmarshal(part, &v); err != nil {
		return nil, fmt.Errorf("part is not a valid json: %w", err)
	}
	res, err := unmarshallValRecursiveStep(v, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall json with options %v: %w", opts, err)
	}
	switch ok := res.(type) {
	case map[string]interface{}:
		return ok, nil
	default:
		return nil, errors.New("part is not a json object")
	}
}

func unmarshallValRecursiveStep(v interface{}, opts ...UnmarshalOpts) (interface{}, error) {
	switch vv := v.(type) {
	case []interface{}:
		return unmarshallArrRecursiveStep(vv, opts...)
	case map[string]interface{}:
		return unmarshallObjRecursiveStep(vv, opts...)
	case string:
		return decodeStringRecursive(vv, opts...)
	default:
		return v, nil
	}
}

func unmarshallArrRecursiveStep(a []interface{}, opts ...UnmarshalOpts) ([]interface{}, error) {
	res := make([]interface{}, len(a))
	for i, v := range a {
		switch vv := v.(type) {
		case []interface{}:
			aa, err := unmarshallArrRecursiveStep(vv, opts...)
			if err != nil {
				return nil, err
			}
			res[i] = aa
		case map[string]interface{}:
			oo, err := unmarshallObjRecursiveStep(vv, opts...)
			if err != nil {
				return nil, err
			}
			res[i] = oo
		default:
			vvv, err := unmarshallValRecursiveStep(vv, opts...)
			if err != nil {
				return nil, err
			}
			res[i] = vvv
		}
	}
	return res, nil
}

func unmarshallObjRecursiveStep(o map[string]interface{}, opts ...UnmarshalOpts) (map[string]interface{}, error) {
	res := make(map[string]interface{})
	for k, v := range o {
		switch vv := v.(type) {
		case []interface{}:
			aa, err := unmarshallArrRecursiveStep(vv, opts...)
			if err != nil {
				return nil, err
			}
			res[k] = aa
		case map[string]interface{}:
			oo, err := unmarshallObjRecursiveStep(vv, opts...)
			if err != nil {
				return nil, err
			}
			res[k] = oo
		default:
			if find(ConvertDate, opts) {
				vv = tryDateConversion(k, vv)
			}
			if find(Recursive, opts) {
				vvv, err := unmarshallValRecursiveStep(vv, opts...)
				if err != nil {
					return nil, err
				}
				res[k] = vvv
			} else {
				res[k] = vv
			}
		}
	}
	return res, nil
}

func tryDateConversion(key string, value interface{}) interface{} {
	if key == "iat" || key == "exp" || key == "nbf" {
		if epoch, ok := value.(float64); ok {
			// update map with time from epoch to human format
			return time.Unix(int64(epoch), 0).UTC().String()
		}
	}
	return value
}

func decodeStringRecursive(v string, opts ...UnmarshalOpts) (interface{}, error) {
	if guessIfJwt(v) && isDecodableJwt(v) {
		j, err := ParseJgo(v, opts...)
		if err != nil {
			return nil, err
		}
		return j, nil
	}
	return v, nil
}

// guessIfJwt is an approximate but fast guess for isDecodableJwt
func guessIfJwt(s string) bool {
	if len(s) < 3 {
		return false
	}
	if s[0:3] == "eyJ" && strings.Count(s, ".") == 2 {
		return true
	}
	return false
}

func isDecodableJwt(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts[0:2] {
		d, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return false
		}
		if !json.Valid(d) {
			return false
		}
	}
	return true
}
