package io

import (
	"path"

	"github.com/thomaschiozzi-tndigit/jgo/internal/jwt"
)

type SourceType int

const (
	SourceDefault SourceType = iota
	SourcePath
	SourceUrl
	SourceStdin
)

// Source is a wrapper for a source that can provide a JWT
type Source interface {
	GetJwt() (string, error)
}

func NewSource(st SourceType, value string) Source {
	switch st {
	case SourcePath:
		return jwt.NewJwtFileSource(value)
	case SourceUrl:
		return jwt.NewUrlJwtSource(value)
	case SourceDefault:
		return jwt.NewStdinJwtSource(value)
	default:
		return NewSource(autoDetectsSourceTypeFromValue(value), value)
	}
}

// autoDetectSource tries to automatically infer source from the value - this
// should be used as a fallback strategy and behaviour on this function
// should not be heavily relied upon
func autoDetectsSourceTypeFromValue(value string) SourceType {
	v := []rune(value)
	if len(v) < 3 {
		// not a clue on what this could be, probably an error
		return SourceStdin
	}
	if guessIfStdin(value) {
		return SourceStdin
	}
	if guessIfUrl(value) {
		return SourceUrl
	}
	if guessIfPath(value) {
		return SourcePath
	}
	return SourceStdin
}

func guessIfStdin(value string) bool {
	if value[0:3] == "eyJ" {
		return true
	}
	return false
}

func guessIfUrl(value string) bool {
	if value[0:4] == "http" {
		return true
	}
	return false
}

func guessIfPath(value string) bool {
	ext := path.Ext(value)
	if ext == "" || ext == ".txt" || ext == ".jwt" {
		return true
	}
	return false
}
