package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
)

// RunGraphQLTest executes GraphQL security tests and returns findings directly.
// It is the library entry point for programmatic usage (e.g. from Guard),
// performing the same core work as the CLI minus reporter output and LLM triage.
func RunGraphQLTest(ctx context.Context, config GraphQLConfig) ([]*model.Finding, error) {
	config.setDefaults()

	log.SetVerbose(config.Verbose)

	graphqlVerboseLog(config.Verbose, "Starting GraphQL security test")
	graphqlVerboseLog(config.Verbose, "Target: %s%s", config.Target, config.Endpoint)

	if config.Target == "" {
		return nil, fmt.Errorf("target URL is required")
	}

	// Load configs
	authConfig, _, err := loadConfigs(config.Auth, config.Roles)
	if err != nil {
		return nil, err
	}

	// Parse custom headers
	customHeaders, err := ParseCustomHeaders(config.Headers)
	if err != nil {
		return nil, fmt.Errorf("invalid custom header: %w", err)
	}

	// Create HTTP client with proxy, TLS, timeout
	httpClient, err := createGraphQLHTTPClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Wrap HTTP client with rate limiting
	rateLimitedClient := wrapWithRateLimiting(httpClient, config)

	// Get schema
	schema, err := fetchSchema(ctx, config, rateLimitedClient, customHeaders)
	if err != nil {
		return nil, err
	}

	reportSchemaInfo(schema, config.Verbose)

	if config.DryRun {
		graphqlDryRunLog(config.DryRun, "Would run security checks against %d queries, %d mutations",
			len(schema.Queries), len(schema.Mutations))
		return nil, nil
	}

	// Build auth configs for scanner
	authConfigs, err := buildAuthConfigs(authConfig)
	if err != nil {
		return nil, err
	}

	// Run security checks with rate-limited client
	endpoint := config.Target + config.Endpoint
	findings, _ := runSecurityChecks(ctx, schema, rateLimitedClient, endpoint, config, authConfigs, nil, customHeaders)

	return findings, nil
}

// setDefaults fills zero-valued fields with sensible defaults for library usage.
// When hadrian is invoked via CLI, cobra flags provide these defaults; for
// direct library callers the fields may be unset.
func (c *GraphQLConfig) setDefaults() {
	if c.Endpoint == "" {
		c.Endpoint = "/graphql"
	}
	if c.Output == "" {
		c.Output = "json"
	}
	if c.RateLimit <= 0 {
		c.RateLimit = 5.0
	}
	if c.RateLimitBackoff == "" {
		c.RateLimitBackoff = "exponential"
	}
	if c.RateLimitMaxWait <= 0 {
		c.RateLimitMaxWait = 60 * time.Second
	}
	if c.RateLimitMaxRetries <= 0 {
		c.RateLimitMaxRetries = 5
	}
	if len(c.RateLimitStatusCodes) == 0 {
		c.RateLimitStatusCodes = []int{429, 503}
	}
	if c.Timeout <= 0 {
		c.Timeout = 30
	}
	if c.DepthLimit <= 0 {
		c.DepthLimit = 10
	}
	if c.ComplexityLimit <= 0 {
		c.ComplexityLimit = 1000
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}
}
