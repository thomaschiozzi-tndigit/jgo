package jgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type PrintOpts int

const (
	reserved PrintOpts = iota
	Indent
	Color
	Jsonify
)

const PrintKeyColor = "\033[36m"
const ColorNone = "\033[0m"
const PrintIndentToken = "\t"
const PrintJsonPrefix = ""

var ErrPrettyPrint = errors.New("failed to pretty print for the following reason")

func (j *Jgo) PrettyPrint(opts ...PrintOpts) ([]byte, error) {
	ok, why := isSupported(opts...)
	if !ok {
		return nil, errors.New(why)
	}
	var out []byte
	var err error
	if find(Jsonify, opts) {
		out, err = printJsonShape(j, opts...)
	} else {
		out, err = printCustomShape(j, opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPrettyPrint, err)
	}
	if find(Color, opts) {
		out = colorize(out)
	}
	return out, nil
}

func printJsonShape(j *Jgo, opts ...PrintOpts) ([]byte, error) {
	if find(Indent, opts) {
		return json.MarshalIndent(j, PrintJsonPrefix, PrintIndentToken)
	}
	return json.Marshal(j)
}

func printCustomShape(j *Jgo, opts ...PrintOpts) ([]byte, error) {
	var b bytes.Buffer
	var bb []byte
	var err error
	if find(Indent, opts) {
		bb, err = json.MarshalIndent(map[string]interface{}(j.Head), PrintJsonPrefix, PrintIndentToken)
	} else {
		bb, err = json.Marshal(map[string]interface{}(j.Head))
	}
	if err != nil {
		return nil, err
	}
	b.Write(bb)
	b.WriteString("\n.\n")
	if find(Indent, opts) {
		bb, err = json.MarshalIndent(map[string]interface{}(j.Clams), PrintJsonPrefix, PrintIndentToken)
	} else {
		bb, err = json.Marshal(map[string]interface{}(j.Clams))
	}
	b.Write(bb)
	b.WriteString("\n.\n")
	b.WriteString(j.Signature)
	return b.Bytes(), nil
}

func isSupported(opts ...PrintOpts) (bool, string) {
	if !find(Indent, opts) && find(Color, opts) {
		return false, "unsupported print combination: non-indented but colored input"
	}
	return true, ""
}

func colorize(v []byte) []byte {
	if len(v) == 0 {
		return v
	}
	indentWindows := len(PrintIndentToken)
	var b bytes.Buffer
	var isColored bool
	var cc string
	isColored = false
	s := string(v)
	for i, c := range s {
		cc = string(c)
		if cc != `"` {
			b.WriteString(cc)
			continue
		}
		if isColored {
			b.WriteString(cc)
			b.WriteString(ColorNone)
			isColored = false
		} else {
			if s[(i-indentWindows):i] == PrintIndentToken {
				b.WriteString(PrintKeyColor)
			}
			b.WriteString(cc)
			isColored = true
		}
	}
	return b.Bytes()
}
