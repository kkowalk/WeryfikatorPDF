//go:build !windows

package main

import (
	"fmt"
	"os"
)

func launchedFromExplorer() bool { return false }

func runGUI([]string) int {
	fmt.Fprintln(os.Stderr, "Okno programu jest dostępne tylko w systemie Windows; użyj trybu konsolowego.")
	return 2
}
