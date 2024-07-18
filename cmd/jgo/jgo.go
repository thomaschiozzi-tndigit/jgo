package main

import (
	"context"
	"os"

	"github.com/thomaschiozzi-tndigit/jgo/internal/cli"
)

func main() {
	res := cli.Run(context.TODO())
	os.Exit(res)
}
