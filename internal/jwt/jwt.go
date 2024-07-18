package jwt

import (
	"fmt"

	"github.com/thomaschiozzi-tndigit/jgo/internal/decode"
	"github.com/thomaschiozzi-tndigit/jgo/internal/jgo"
)

// Jwt is a utility struct that includes all possible representation of a
// jwt
type Jwt struct {
	Raw      string
	rawParts *decode.B64Parts
	decParts *decode.Parts
	jgo      *jgo.Jgo
}

func (j *Jwt) GetRawParts() (decode.B64Parts, error) {
	if j.rawParts != nil {
		return *j.rawParts, nil
	}
	return decode.ParseRawParts(j.Raw)
}

func (j *Jwt) GetParts() (decode.Parts, error) {
	if j.decParts != nil {
		return *j.decParts, nil
	}
	raw, err := j.GetRawParts()
	if err != nil {
		return decode.Parts{}, fmt.Errorf("jwt has invalid raw parts: %w", err)
	}
	return raw.ToDecodedParts()
}

func (j *Jwt) GetJgo() (jgo.Jgo, error) {
	if j.jgo != nil {
		return *j.jgo, nil
	}
	res, err := jgo.ParseJgo(j.Raw)
	return *res, err
}

func NewJwt(jwt string, opts ...jgo.UnmarshalOpts) (*Jwt, error) {
	b64parts, err := decode.ParseRawParts(jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwt in parts: %w", err)
	}
	parts, err := b64parts.ToDecodedParts()
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt parts: %w")
	}
	unmarshalled, err := jgo.ParseJgo(jwt, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall jwt: %w", err)
	}
	return &Jwt{Raw: jwt, rawParts: &b64parts, decParts: &parts, jgo: unmarshalled}, nil
}
