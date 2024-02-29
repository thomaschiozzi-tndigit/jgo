package jwt

// StdinJwtSource is a wrapper for a JWT that is passed in the program froms stdin
type StdinJwtSource struct {
	value string
}

func (s *StdinJwtSource) GetJwt() (string, error) {
	return s.value, nil
}
