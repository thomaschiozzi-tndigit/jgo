# jgo
Miscellaneous and utility tools for JOSE/JWT.

# Features
The following core features are currently supported
1. JWT Decoding.

# Requirements
The Go programming language is required to build and execute this module. To download Go, you can find more here https://go.dev/doc/install .

# Install the Project
Open the terminal in this folder, then

    cd cmd
    cd jgo
    go build

This should create a `jgo.exe` or a `jgo` file (depends on OS and build options) and will also create a binary app whose path can be viewed with `go list -f '{{.Target}}'`.
To use this tool from anywhere in the terminal, add the installation directory to the system shell path. For more details, see [official manual the manual page](https://go.dev/doc/tutorial/compile-install).
Finally, run the `go install` command.

# Project Usage
TODO: how to use the tool, maybe with one example?

**IMPORTANT:** Usage options and modality is not guaranteed to be stable until v1.0 is released 

# Roadmap
- [x] Core JWT decode function
- [ ] CLI interface for double click usage?
- [ ] Printing nice outputs (configurable from flags)
- [ ] Tests
- [ ] decent/passable argument parser
- [x] decode JWT from stdin
- [x] decode JWT from file
- [x] decode JWT from remote
- [ ] recursively "decode" JWT
- [ ] accept signature key from stdin and validate signature
- [x] validate JWT signature when pub key can be recovered online
- [ ] forge jwt from config file
- [ ] forge jwt from interactive CLI
