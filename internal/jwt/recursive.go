package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
)

type DecodedJwt struct {
	Head      map[string]interface{} `json:"_jgo.jwt.head,omitempty"`
	Clams     map[string]interface{} `json:"_jgo.jwt.claims,omitempty"`
	Signature string                 `json:"_jgo.jwt.signature,omitempty"`
	Parts     *Parts
}

func (j *DecodedJwt) StringWithOpts(opts PrintOpts) string {
	var out bytes.Buffer
	ser, err := json.Marshal(j)
	if err != nil {
		log.Panic(err)
	}
	if err = json.Indent(&out, ser, "", opts.Indent); err != nil {
		log.Panic(err)
	}
	prettyJwt := out.String()
	return colorize(prettyJwt, opts)
}

func (j *DecodedJwt) String() string {
	return j.StringWithOpts(PrintOpts{printIndentToken, printKeyColor})
}

func decodeJwtPartRecursive(part string) (map[string]interface{}, error) {
	if len(part) == 0 {
		return make(map[string]interface{}), nil
	}
	decodedPart, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, err
	}
	if !json.Valid(decodedPart) {
		return nil, fmt.Errorf("decodedPart JWT part is not a valid JSON string")
	}
	var v interface{}
	if err = json.Unmarshal(decodedPart, &v); err != nil {
		return nil, fmt.Errorf("decodedPart JWT part is not a valid JSON: %w", err)
	}
	res, err := decodeValRecursiveStep(v)
	if err != nil {
		return nil, fmt.Errorf("failed recursion in jwt decoding: %w", err)
	}
	switch ok := res.(type) {
	case map[string]interface{}:
		return ok, nil
	default:
		return nil, errors.New("failed to create a dictionary for that map")
	}
}

func guessIfJwt(s string) bool {
	if len(s) < 3 {
		return false
	}
	if s[0:3] == "eyJ" && strings.Count(s, ".") == 2 {
		return true
	}
	return false
}

func decodeStringRecursiveStep(v string) (interface{}, error) {
	if guessIfJwt(v) && IsValid(v) {
		j, err := ParseJwt(v)
		if err != nil {
			return nil, err
		}
		return j, nil
	}
	return v, nil
}

func decodeValRecursiveStep(v interface{}) (interface{}, error) {
	switch vv := v.(type) {
	case []interface{}:
		return decodeArrRecursiveStep(vv)
	case map[string]interface{}:
		return decodeObjRecursiveStep(vv)
	case string:
		return decodeStringRecursiveStep(vv)
	default:
		return v, nil
	}
}

func decodeArrRecursiveStep(a []interface{}) ([]interface{}, error) {
	res := make([]interface{}, len(a))
	for i, v := range a {
		switch vv := v.(type) {
		case []interface{}:
			aa, err := decodeArrRecursiveStep(vv)
			if err != nil {
				return nil, err
			}
			res[i] = aa
		case map[string]interface{}:
			oo, err := decodeObjRecursiveStep(vv)
			if err != nil {
				return nil, err
			}
			res[i] = oo
		default:
			vvv, err := decodeValRecursiveStep(vv)
			if err != nil {
				return nil, err
			}
			res[i] = vvv
		}
	}
	return res, nil
}

func decodeObjRecursiveStep(o map[string]interface{}) (map[string]interface{}, error) {
	res := make(map[string]interface{})
	for k, v := range o {
		switch vv := v.(type) {
		case []interface{}:
			aa, err := decodeArrRecursiveStep(vv)
			if err != nil {
				return nil, err
			}
			res[k] = aa
		case map[string]interface{}:
			oo, err := decodeObjRecursiveStep(vv)
			if err != nil {
				return nil, err
			}
			res[k] = oo
		default:
			vvv, err := decodeValRecursiveStep(vv)
			if err != nil {
				return nil, err
			}
			res[k] = vvv
		}
	}
	return res, nil
}

func ParseJwt(jwt string) (*DecodedJwt, error) {
	parts, err := ParseJwtInParts(jwt)
	if err != nil {
		return nil, err
	}
	head, err := decodeJwtPartRecursive(parts.Head)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt header %s: %w", parts.Head, err)
	}
	claims, err := decodeJwtPartRecursive(parts.ClaimsSet)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt claim set %s: %w", parts.ClaimsSet, err)
	}
	return &DecodedJwt{head, claims, parts.Signature, parts}, nil
}
