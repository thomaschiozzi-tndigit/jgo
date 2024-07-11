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
	switch vv := v.(type) {
	case []interface{}:
		jArr, err := convertDatesSliceRecursiveStep(vv)
		if err != nil {
			return nil, fmt.Errorf("internal error: %w", err)
		}
		out, err := json.Marshal(jArr)
		if err != nil {
			return nil, fmt.Errorf("failed to re-convert claims to json: %w", err)
		}
		return out, nil
	case map[string]interface{}:
		jObj, err := convertDatesMapRecursiveStep(vv)
		if err != nil {
			return nil, fmt.Errorf("internal error: %w", err)
		}
		out, err := json.Marshal(jObj)
		if err != nil {
			return nil, fmt.Errorf("failed to re-convert claims to json: %w", err)
		}
		return out, nil
	default:
		return data, nil
	}
}

func convertDatesSliceRecursiveStep(jsonArr []interface{}) ([]interface{}, error) {
	res := make([]interface{}, len(jsonArr))
	for i, v := range jsonArr {
		switch vv := v.(type) {
		case []interface{}:
			arr, err := convertDatesSliceRecursiveStep(vv)
			if err != nil {
				return nil, err
			}
			res[i] = arr
		case map[string]interface{}:
			dic, err := convertDatesMapRecursiveStep(vv)
			if err != nil {
				return nil, err
			}
			res[i] = dic
		default:
			res[i] = vv
		}
	}
	return res, nil
}

func convertDatesMapRecursiveStep(jsonObj map[string]interface{}) (map[string]interface{}, error) {
	res := make(map[string]interface{})
	for k, v := range jsonObj {
		switch vv := v.(type) {
		case []interface{}:
			arr, err := convertDatesSliceRecursiveStep(vv)
			if err != nil {
				return nil, err
			}
			res[k] = arr
		case map[string]interface{}:
			dic, err := convertDatesMapRecursiveStep(vv)
			if err != nil {
				return nil, err
			}
			res[k] = dic
		default:
			if k == "iat" || k == "exp" || k == "nbf" {
				if epoch, ok := v.(float64); ok {
					// update map with time from epoch to human format
					res[k] = time.Unix(int64(epoch), 0).UTC().String()
					continue
				}
			}
			res[k] = vv
		}
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
