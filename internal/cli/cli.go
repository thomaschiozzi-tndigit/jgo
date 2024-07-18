package cli

import (
	"errors"
	"flag"
	"fmt"

	"github.com/thomaschiozzi-tndigit/jgo/internal/io"
	"github.com/thomaschiozzi-tndigit/jgo/internal/jgo"
)

type SourceOpts struct {
	Path bool
	Url  bool
}

type ResultModifyOpts struct {
	ConvertDates bool
	Recursive    bool
}

type PrintOpts struct {
	NoIndent bool
	NoColor  bool
	AsJson   bool
}

// Opts is a struct wrapper for optional arguments
type Opts struct {
	SourceOpts
	ResultModifyOpts
	PrintOpts
}

// SourceType evaluates the given source based on input flags
func (o *Opts) SourceType() io.SourceType {
	if o.Path && o.Url {
		panic("only one among path and url should be used")
	}
	if o.Path {
		return io.SourcePath
	}
	if o.Url {
		return io.SourceUrl
	}
	return io.SourceDefault
}

func (o *Opts) ToPrintOpts() []jgo.PrintOpts {
	res := make([]jgo.PrintOpts, 0)
	if o.AsJson {
		res = append(res, jgo.Jsonify)
	}
	if !o.NoColor {
		res = append(res, jgo.Color)
	}
	if !o.NoIndent {
		res = append(res, jgo.Indent)
	}
	return res
}

func (o *Opts) ToUnmarshallOpts() []jgo.UnmarshalOpts {
	res := make([]jgo.UnmarshalOpts, 0)
	if o.Recursive {
		res = append(res, jgo.Recursive)
	}
	if o.ConvertDates {
		res = append(res, jgo.ConvertDate)
	}
	return res
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
	flag.BoolVar(&opts.Recursive, "rec", false, "if set, will; try to recursively decode jwt values")
	flag.BoolVar(&opts.ConvertDates, "cvt_dates", false, "if set, convert default epoch claims to ")
	flag.BoolVar(&opts.AsJson, "json", false, "if set, represent output as json")
	flag.BoolVar(&opts.NoColor, "nocolor", false, "if set, print result without colours")
	flag.BoolVar(&opts.NoIndent, "noindent", false, "if set, print result without indents")
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
