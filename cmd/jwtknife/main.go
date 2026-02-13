package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/spencer5cent/jwtknife/internal/report"
	"github.com/spencer5cent/jwtknife/internal/wizard"
)

func main() {
	var exhaustive bool

	flag.BoolVar(&exhaustive, "exhaustive", false, "run all attacks even after a successful exploit")
	flag.Parse()

	cfg := wizard.Config{
		RawJWT:     "",
		Method:     "GET",
		Exhaustive: exhaustive,
	}

	run, err := wizard.Run(cfg, os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	report.PrintHuman(os.Stdout, run)
}
