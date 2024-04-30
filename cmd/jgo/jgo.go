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
	// convert dates from unix to UTC
	if opts.ConvertDates {
		jj, err := j.ConvertEpochsToUTC()
		if err != nil {
			fmt.Printf("failed to convert dates due to following error: %v", err)
			return
		}
		j = jj
	}

	fmt.Println(j.String())

	// verify signature
	if opts.CheckSignature {
		keys, err := jwt.PKCStore(j)
		if err != nil {
			fmt.Println("\nskipped signature verification: this is probably not a JWT access token", err)
			return
		}
		if ok, _ := jwt.VerifySignature(jwtValue, keys); !ok {
			fmt.Println("\nFailed to verify signature >:(")
		} else {
			fmt.Println("\nSignature is valid! :)")
		}
	}
}
