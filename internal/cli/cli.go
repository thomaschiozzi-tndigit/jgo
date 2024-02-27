package cli

import (
	"errors"
	"flag"
	"fmt"
)

// CliOpts is a struct wrapper for optional arguments
type CliOpts struct {
	Path bool
	Url  bool
}

// CliPosArgs is struct wrapper for mandatory positional arguments
type CliPosArgs struct {
	Source string
}

// Validate checks if the currently stored value in CliOpts satisfy the requirements
func validate(opt *CliOpts, args *CliPosArgs) error {
	if opt.Path && opt.Url {
		return errors.New("invalid option: both Path and Url flags were set")
	}
	if args.Source == "" {
		return errors.New("missing mandatory attribute Source")
	}
	return nil
}

func ParseArgs() (*CliOpts, *CliPosArgs, error) {
	opts := &CliOpts{}
	pargs := &CliPosArgs{}
	flag.BoolVar(&opts.Path, "path", false, "if set, interpret input as a file Path containing a JWT as only content")
	flag.BoolVar(&opts.Url, "url", false, "if set, interpret input as an URL where a JWT is stored")
	flag.Parse()
	// TODO: expand and review flag.Usage()
	if flag.NArg() == 0 {
		return nil, nil, fmt.Errorf("missing mandatory positional argument Source")
	}
	inputs := flag.Args()
	pargs.Source = inputs[0]
	err := validate(opts, pargs)
	if err != nil {
		return nil, nil, err
	}
	return opts, pargs, nil
}
