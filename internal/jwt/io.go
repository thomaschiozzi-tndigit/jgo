package jwt

// Source is a wrapper for a source that can provide a JWT
type Source interface {
	GetJwt() (string, error)
}

func NewSource(path bool, url bool, value string) Source {
	// TODO: implement "enum" for sourceType (according rto what Go currently allows...)
	if path && url {
		panic("only one among path and url should be used, TODO: handle error properly by returning usage and quitting")
	}
	if path {
		return &FileJwtSource{path: value}
	}
	if url {
		return &UrlJwtSource{url: value}
	}
	return &StdinJwtSource{value: value}
}
