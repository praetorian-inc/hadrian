package main

import (
	"os"

	"github.com/praetorian-inc/hadrian/pkg/runner"
)

func main() {
	if err := runner.Run(); err != nil {
		os.Exit(1)
	}
}
