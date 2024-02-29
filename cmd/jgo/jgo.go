package main

import (
	"flag"
	"fmt"
	"github.com/thomaschiozzi-tndigit/jgo/internal/cli"
	"github.com/thomaschiozzi-tndigit/jgo/internal/jwt"
)

func main() {
	opts, pargs, err := cli.ParseArgs()
	if err != nil {
		fmt.Println(err)
		flag.Usage()
	}
	source := jwt.NewSource(opts.Path, opts.Url, pargs.Source)
	jwtValue, err := source.GetJwt()
	if err != nil {
		fmt.Println("unable to fetch jwt from source: obtained error", err)
		return
	}
	j, err := jwt.ParseJwt(jwtValue)
	if err != nil {
		fmt.Printf("unable to decode the input string, obtained error: %v", err.Error())
		return
	}
	fmt.Println(j.String())
}
