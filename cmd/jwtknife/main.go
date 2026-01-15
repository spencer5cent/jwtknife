package main

import (
	"fmt"
	"os"

	"jwtknife/internal/report"
	"jwtknife/internal/wizard"
)

func main() {
	cfg := wizard.Config{
		RawJWT: "",
		Method: "GET",
	}

	run, err := wizard.Run(cfg, os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	report.PrintHuman(os.Stdout, run)
}
