package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// newFlagSet uses ContinueOnError so dispatch can return a proper
// exit code rather than letting flag os.Exit on its own.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", name)
		fs.PrintDefaults()
	}
	return fs
}

// multiString registers a flag that may appear more than once.
func multiString(fs *flag.FlagSet, name, usage string) *[]string {
	v := &multiStringValue{}
	fs.Var(v, name, usage)
	return (*[]string)(v)
}

type multiStringValue []string

func (m *multiStringValue) String() string     { return strings.Join(*m, ",") }
func (m *multiStringValue) Set(s string) error { *m = append(*m, s); return nil }
