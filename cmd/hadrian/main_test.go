package main

import (
	"testing"
)

func TestMain(t *testing.T) {
	// This test verifies that main() can be called without panicking.
	// Since main() calls runner.Run() which returns an error and exits,
	// we just verify the package compiles correctly.
	// The actual functionality is tested in pkg/runner/run_test.go
	t.Log("main package compiles successfully")
}
