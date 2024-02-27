package jwt

import "os"

// FileJwtSource reads a jwt from a file
type FileJwtSource struct {
	path string
}

func (f *FileJwtSource) GetJwt() (string, error) {
	jwtB, err := os.ReadFile(f.path)
	if err != nil {
		return "", err
	}
	jwtS := string(jwtB)
	return jwtS, nil
}
