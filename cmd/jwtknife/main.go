package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"jwtknife/internal/report"
	"jwtknife/internal/wizard"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Paste the JWT (you can include 'Bearer '): ")
	raw, _ := reader.ReadString('\n')
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "Bearer ")

	cfg := wizard.Config{
		RawJWT: raw,
		Method: "GET",
	}

	run, err := wizard.Run(cfg, os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	report.PrintHuman(os.Stdout, run)
}
