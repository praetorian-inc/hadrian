package runner

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Run is the main entry point for the Hadrian CLI
func Run() error {
	rootCmd := &cobra.Command{
		Use:   "hadrian",
		Short: "Hadrian - API Security Testing Framework",
		Long:  `Hadrian is a security testing framework for REST, GraphQL, and gRPC APIs that tests for OWASP vulnerabilities and custom security issues.`,
	}

	rootCmd.PersistentFlags().Bool("no-banner", false, "Suppress the startup banner")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		noBanner, _ := cmd.Root().PersistentFlags().GetBool("no-banner")
		if !noBanner {
			printBanner()
		}
	}

	rootCmd.AddCommand(newTestCmd())
	rootCmd.AddCommand(newParseCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd.Execute()
}

// newTestCmd creates the test command with subcommands
func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run security tests against an API",
		Long:  `Run security tests against an API. Use 'test rest' for REST APIs, 'test graphql' for GraphQL APIs, or 'test grpc' for gRPC APIs.`,
	}

	// Add subcommands
	cmd.AddCommand(newTestRestCmd())
	cmd.AddCommand(newTestGraphQLCmd())
	cmd.AddCommand(newTestGRPCCmd())

	return cmd
}

// newParseCmd creates the parse command
func newParseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parse <api-spec-file>",
		Short: "Parse API specification and show operations",
		Long:  `Parse an API specification file (OpenAPI, Swagger, Postman) and display all operations.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return parseCmdHandler(args[0])
		},
	}

	return cmd
}

// newVersionCmd creates the version command
func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show Hadrian version",
		RunE:  runVersion,
	}

	return cmd
}

func runVersion(cmd *cobra.Command, args []string) error {
	fmt.Printf("Hadrian v%s\n", Version)
	return nil
}

// parseCmdHandler parses and displays API specification details
func parseCmdHandler(apiSpecFile string) error {
	spec, err := parseAPISpec(apiSpecFile)
	if err != nil {
		return err
	}

	fmt.Printf("API: %s (v%s)\n", spec.Info.Title, spec.Info.Version)
	fmt.Printf("Base URL: %s\n", spec.BaseURL)
	fmt.Printf("Operations: %d\n\n", len(spec.Operations))

	for _, op := range spec.Operations {
		fmt.Printf("  %s %s\n", op.Method, op.Path)
		if op.RequiresAuth {
			fmt.Printf("    [Auth Required]\n")
		}
		if len(op.PathParams) > 0 {
			fmt.Printf("    Path params: ")
			for i, p := range op.PathParams {
				if i > 0 {
					fmt.Printf(", ")
				}
				fmt.Printf("{%s}", p.Name)
			}
			fmt.Println()
		}
	}

	return nil
}

// hasLLMConfig checks if LLM provider is configured
func hasLLMConfig() bool {
	return os.Getenv("OLLAMA_HOST") != ""
}

// verboseLog writes a formatted message to w only if verbose mode is enabled.
func verboseLog(w io.Writer, verbose bool, format string, args ...interface{}) {
	if verbose {
		_, _ = fmt.Fprintf(w, "[VERBOSE] "+format+"\n", args...)
	}
}

// dryRunLog writes a formatted message to w only if dry-run mode is enabled.
func dryRunLog(w io.Writer, dryRun bool, format string, args ...interface{}) {
	if dryRun {
		_, _ = fmt.Fprintf(w, "[DRY-RUN] "+format+"\n", args...)
	}
}
