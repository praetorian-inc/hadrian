package runner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
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

func TestPrintBanner(t *testing.T) {
	output := captureStdout(func() {
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
	rootCmd := &cobra.Command{
		Use: "hadrian",
	}
	rootCmd.PersistentFlags().Bool("no-banner", false, "Suppress the startup banner")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		noBanner, _ := cmd.Root().PersistentFlags().GetBool("no-banner")
		if !noBanner {
			printBanner()
		}
	}

	noopCmd := &cobra.Command{
		Use:  "noop",
		RunE: func(cmd *cobra.Command, args []string) error { return nil },
	}
	rootCmd.AddCommand(noopCmd)

	output := captureStdout(func() {
		rootCmd.SetArgs([]string{"--no-banner", "noop"})
		err := rootCmd.Execute()
		assert.NoError(t, err)
	})

	assert.NotContains(t, output, "Praetorian Security", "banner should be suppressed with --no-banner")
	assert.True(t, strings.TrimSpace(output) == "" || !strings.Contains(output, "Praetorian Security"),
		"no banner output expected when --no-banner is set")
}
