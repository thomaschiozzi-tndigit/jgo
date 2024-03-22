package cli

import (
	"errors"
	"flag"
	"fmt"
)

// Opts is a struct wrapper for optional arguments
type Opts struct {
	Path bool
	Url  bool
}

// PosArgs is struct wrapper for mandatory positional arguments
type PosArgs struct {
	Source string
}

// Validate checks if the currently stored value in CliOpts satisfy the requirements
func validate(opt *Opts, args *PosArgs) error {
	if opt.Path && opt.Url {
		return errors.New("invalid option: both Path and Url flags were set")
	}
	if args.Source == "" {
		return errors.New("missing mandatory attribute Source")
	}
	return nil
}

func ParseArgs() (*Opts, *PosArgs, error) {
	opts := &Opts{}
	posArgs := &PosArgs{}
	flag.BoolVar(&opts.Path, "path", false, "if set, interpret input as a file Path containing a JWT as only content")
	flag.BoolVar(&opts.Url, "url", false, "if set, interpret input as an URL where a JWT is stored")
	//flag.BoolVar(&opts.Pretty, "pretty", false, "if set, prettify the result")
	flag.Parse()
	// TODO: expand and review flag.Usage()
	if flag.NArg() == 0 {
		return nil, nil, fmt.Errorf("missing mandatory positional argument Source")
	}
	inputs := flag.Args()
	posArgs.Source = inputs[0]
	err := validate(opts, posArgs)
	if err != nil {
		return nil, nil, err
	}
	return opts, posArgs, nil
}
