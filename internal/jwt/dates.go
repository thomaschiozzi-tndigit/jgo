package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// recursively convert claims: (1) iat, (2) exp, (3) nbf from
// unix time (in seconds) to UTC date
func convertE2UTC(data []byte) ([]byte, error) {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, errors.New("claims are not a json")
	}
	m := v.(map[string]interface{})
	for k, v := range m {
		switch v.(type) {
		case map[string]interface{}:
			v1, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("internal error: %w", err)
			}
			v2, err := convertE2UTC(v1)
			if err != nil {
				return nil, err
			}
			m[k] = v2
		default:
			if k == "iat" || k == "exp" || k == "nbf" {
				if epoch, ok := v.(float64); ok {
					// update map with time from epoch to human format
					m[k] = time.Unix(int64(epoch), 0).UTC().String()
				}
			}

		}
	}
	res, err := json.Marshal(m)
	if err != nil {
		return nil, errors.New("failed to re-convert claims to json")
	}
	return res, nil
}

// ConvertEpochsToUTC will try to convert epoch-based claims ("iat", "nbf" and
// "exp") and convert them to a .
func (j *Jwt) ConvertEpochsToUTC() (*Jwt, error) {
	// deep copy input for safety
	jj := new(Jwt)
	jj.Head = j.Head
	jj.Signature = j.Signature
	claims, err := convertE2UTC([]byte(j.ClaimsSet))
	if err != nil {
		jj.ClaimsSet = j.ClaimsSet
		return jj, fmt.Errorf("unable to decode claims: %w", err)
	}
	jj.ClaimsSet = string(claims)
	return jj, nil
}
