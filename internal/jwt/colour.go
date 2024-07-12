package jwt

import "strings"

const printKeyColor = "\033[36m"
const colorNone = "\033[0m"

// colorize will print a colored decoded jwt
// currently does not work properly if there is no indent
func colorize(s string, opts PrintOpts) string {
	if len(s) == 0 {
		return ""
	}
	if opts.KeyColor == "" {
		return s
	}
	indentWindows := len(opts.Indent)
	var b strings.Builder
	var isColored bool
	var cc string
	isColored = false
	for i, c := range s {
		cc = string(c)
		if cc != `"` {
			b.WriteString(cc)
			continue
		}
		if isColored {
			b.WriteString(cc)
			b.WriteString(colorNone)
			isColored = false
		} else {
			if s[(i-indentWindows):i] == opts.Indent {
				b.WriteString(opts.KeyColor)
			}
			b.WriteString(cc)
			isColored = true
		}
	}
	return b.String()
}
