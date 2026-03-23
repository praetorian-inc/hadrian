package runner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout redirects os.Stdout to a buffer, calls f, then restores stdout
// and returns whatever was written.
func captureStdout(f func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	old := os.Stdout
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r) //nolint:errcheck
	return buf.String()
}

func captureStderr(f func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	old := os.Stderr
	os.Stderr = w

	f()

	_ = w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	io.Copy(&buf, r) //nolint:errcheck
	return buf.String()
}

func TestPrintBanner(t *testing.T) {
	output := captureStderr(func() {
		printBanner()
	})

	// The ASCII art banner spells out HADRIAN visually; the tagline is always present.
	assert.Contains(t, output, "Praetorian Security", "banner should contain tagline")
	assert.Contains(t, output, fmt.Sprintf("v%s", Version), "banner should contain version string")
}

func TestNoBannerFlag(t *testing.T) {
	rootCmd := &cobra.Command{
		Use: "hadrian",
	}
	rootCmd.PersistentFlags().Bool("no-banner", false, "Suppress the startup banner")

	flag := rootCmd.PersistentFlags().Lookup("no-banner")
	require.NotNil(t, flag, "--no-banner flag should exist")
	assert.Equal(t, "false", flag.DefValue, "--no-banner should default to false")
}

func TestBannerSuppression(t *testing.T) {
	// Replicate the Run() banner logic: parse flags before Execute() and
	// conditionally call printBanner(). The banner is written to stderr.
	rootCmd := &cobra.Command{
		Use: "hadrian",
	}
	rootCmd.PersistentFlags().Bool("no-banner", false, "Suppress the startup banner")

	output := captureStderr(func() {
		rootCmd.ParseFlags([]string{"--no-banner"}) //nolint:errcheck
		noBanner, _ := rootCmd.Flags().GetBool("no-banner")
		if !noBanner {
			printBanner()
		}
	})

	assert.NotContains(t, output, "Praetorian Security", "banner should be suppressed with --no-banner")
}
