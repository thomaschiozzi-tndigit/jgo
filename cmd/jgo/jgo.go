package main

import (
	"flag"
	"fmt"
	"github.com/thomaschiozzi-tndigit/jgo/internal/jwt"
	"os"
)

func main() {
	fmt.Println("Program inputs", os.Args)
	if flag.NArg() == 0 {
		fmt.Println("missing mandatory input: provided no inputs")
		flag.Usage()
		return
	}
	inputs := flag.Args()
	inJwt := inputs[0]
	j, err := jwt.ParseJwt(inJwt)
	if err != nil {
		fmt.Printf("unable to decode the input string, obtained error %v", err.Error())
		return
	}
	fmt.Println(j.ToString())
}
