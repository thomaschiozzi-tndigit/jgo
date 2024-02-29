# jgo
Miscellaneous and utility tools for JOSE/JWT 

# Install the Project
Open the terminal in this folder, then

    cd cmd
    cd jgo
    go build

This should create a `jgo.exe` or a `jgo` file (depends on OS and build options) and will also create a binary app whose path can be viewed with `go list -f '{{.Target}}'`.
To use this from anywhere, add the installation directory to the system shell path. For more details, see [official manual the manual page](https://go.dev/doc/tutorial/compile-install).
Finally, run the `go install` command.

# Project Usage
TODO: instruction for non-Go developers

**IMPORTANT:** Usage is not guaranteed to be stable until v1.0 is released 

# TODO
- [x] Core JWT decode function
- [ ] Printing nice outputs (configurable from flags)
- [ ] Tests
- [ ] decent/passable argument parser
- [ ] decode JWT from stdin
- [ ] decode JWT from file
- [ ] decode JWT from remote
- [ ] recursively "decode" JWT
- [ ] accept signature key from stdin and validate signature
- [ ] validate JWT signature when pub key can be recovered online
- [ ] forge jwt from config file
- [ ] forge jwt from interactive CLI
