package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/thomaschiozzi-tndigit/jgo/internal/version"
)

const helpHeader = `

jgo is a JWT/JOSE decode and visualization tool. Fetch, parse decode and
visualize JOSE and JWT locally or around the web.

Example usage - remote JWT:
    jgo https://oidc.registry.servizicie.interno.gov.it/.well-known/openid-federation
Example usage - JWT argument:
    jgo eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
`

var cliUsage string

func createCliUsage() string {
	var b strings.Builder
	b.WriteString("jgo - JWT visualization tool [" + version.Version + "]" + `

Usage: jgo [source_opts] [modify_options] [print_opts] <source>` + helpHeader)
	b.WriteString(`

Positional argument(s)
    <source> the source of the JWT; the JWT can be for a remote source, from
             a local file or passed directly; the tool will try to infer
             location based on the value of the argument

Command options
    [source_opts]
    --path  if set, interpret source as a file path containing a jwt 
    --url   if set, interpret input as an URL where a JWT is stored
    [modify_opts]
    --rec       if set, will try to recursively decode jwt values in the header
                and claims of the source
    --cvt_dates	if set, convert default epoch claims to UTC standard timezone
    [print_opts]
    --json      if set, the output is represented as a json with a
                predetermined namespace with value _jgo.jwt for the jwt header,
                claims and signature 
    --noindent  if set, will not pretty indent the out; currently colored
                output must be indented, as such --noindent must be used
                with --nocolor
    --nocolor   if set, will not color the output
`)
	return b.String()
}

func initCliUsage() {
	if cliUsage != "" {
		return
	}
	cliUsage = createCliUsage()
}

func OverrideUsage() {
	initCliUsage()
	flag.Usage = func() {
		fmt.Println(cliUsage)
	}
}
