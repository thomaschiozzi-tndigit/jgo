package cli

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/thomaschiozzi-tndigit/jgo/internal/io"
	"github.com/thomaschiozzi-tndigit/jgo/internal/jwt"
	"github.com/thomaschiozzi-tndigit/jgo/internal/version"
)

const (
	Success = iota
	ErrUsage
	ErrSource
	ErrJwtParse
	ErrJwtOut
)

func Run(ctx context.Context) int {
	logger := log.New(os.Stdout, "ERROR: ", log.Lshortfile)
	OverrideUsage()
	opts, args, err := ParseArgs()
	if err != nil {
		logger.Println(err)
		return ErrUsage
	}
	if opts.Version {
		fmt.Printf("jgo v%v", version.Version)
		return Success
	}

	source := io.NewSource(opts.SourceType(), args.Source)
	jwtValue, err := source.GetJwt()
	if err != nil {
		logger.Println(err)
		return ErrSource
	}

	j, err := jwt.NewJwt(jwtValue, opts.ToUnmarshallOpts()...)
	if err != nil {
		logger.Println(err)
		return ErrJwtParse
	}
	val, err := j.GetJgo()
	if err != nil {
		logger.Println(err)
		return ErrJwtParse
	}
	out, err := (&val).PrettyPrint(opts.ToPrintOpts()...)
	if err != nil {
		logger.Println(err)
		return ErrJwtOut
	}
	fmt.Println(string(out))
	return Success
}
