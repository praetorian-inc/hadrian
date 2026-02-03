# OOB Detection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Add Out-of-Band (OOB) detection capability to Hadrian for SSRF and callback-based vulnerability testing.

**Architecture:** Integrate interactsh client library to generate unique callback URLs, inject them into templates via `{{interactsh}}` variable substitution, and poll for interactions after request execution.

**Tech Stack:** Go, github.com/projectdiscovery/interactsh/pkg/client, existing Hadrian template system

---

## Verified APIs (from evidence-based analysis)

### Template Structure (`pkg/templates/template.go`)

**Source:** pkg/templates/template.go (lines 7-29)
```go
type Template struct {
    ID               string           `yaml:"id"`
    Info             TemplateInfo     `yaml:"info"`
    EndpointSelector EndpointSelector `yaml:"endpoint_selector"`
    RoleSelector     RoleSelector     `yaml:"role_selector"`
    TestPhases       *TestPhases      `yaml:"test_phases,omitempty"`
    HTTP             []HTTPTest       `yaml:"http,omitempty"`
    GraphQL          []GraphQLTest    `yaml:"graphql,omitempty"`
    Detection        Detection        `yaml:"detection"`
}
```

### GraphQLTest Structure (`pkg/templates/template.go`)

**Source:** pkg/templates/template.go (lines 133-152)
```go
type GraphQLTest struct {
    Query         string      `yaml:"query"`
    Variables     interface{} `yaml:"variables,omitempty"`
    OperationName string      `yaml:"operation_name,omitempty"`
    Auth          string      `yaml:"auth,omitempty"`
    Matchers      []Matcher   `yaml:"matchers,omitempty"`
    Repeat        int         `yaml:"repeat,omitempty"`
    RateLimit     *RateLimit  `yaml:"rate_limit,omitempty"`
    Backoff       *Backoff    `yaml:"backoff,omitempty"`
    StoreResponseFields map[string]string `yaml:"store_response_fields,omitempty"`
    UseStoredField      string            `yaml:"use_stored_field,omitempty"`
}
```

### HTTPTest Structure (`pkg/templates/template.go`)

**Source:** pkg/templates/template.go (lines 114-130)
```go
type HTTPTest struct {
    Method   string            `yaml:"method"`
    Path     string            `yaml:"path"`
    Headers  map[string]string `yaml:"headers"`
    Body     string            `yaml:"body,omitempty"`
    Repeat   int               `yaml:"repeat,omitempty"`
    RateLimit *RateLimit       `yaml:"rate_limit,omitempty"`
    Backoff   *Backoff         `yaml:"backoff,omitempty"`
    Matchers []Matcher         `yaml:"matchers"`
}
```

### Indicator Structure (`pkg/templates/template.go`)

**Source:** pkg/templates/template.go (lines 171-179)
```go
type Indicator struct {
    Type       string      `yaml:"type,omitempty"`        // status_code, body_field, regex_match, sensitive_fields_exposed
    StatusCode interface{} `yaml:"status_code,omitempty"`
    BodyField  string      `yaml:"body_field,omitempty"`
    Value      interface{} `yaml:"value,omitempty"`
    Pattern    string      `yaml:"pattern,omitempty"`
    Fields     []string    `yaml:"fields,omitempty"`
    Exists     *bool       `yaml:"exists,omitempty"`
}
```

### Executor Interface (`pkg/templates/execute.go`)

**Source:** pkg/templates/execute.go (lines 16-22)
```go
type Executor struct {
    client      HTTPClient
    baseURL     string
    requestTracker *RequestTracker
}
```

### Variable Substitution Pattern (`pkg/templates/execute.go`)

**Source:** pkg/templates/execute.go (line ~248 in substituteVariables)
```go
// Pattern: strings.ReplaceAll(query, "{{"+key+"}}", value)
// Already supports arbitrary variables via map[string]string
```

### Evidence Structure (`pkg/model/finding.go`)

**Source:** pkg/model/finding.go (lines 38-47)
```go
type Evidence struct {
    Request  HTTPRequest  `json:"request"`
    Response HTTPResponse `json:"response"`
    SetupResponse  *HTTPResponse `json:"setup_response,omitempty"`
    AttackResponse *HTTPResponse `json:"attack_response,omitempty"`
    VerifyResponse *HTTPResponse `json:"verify_response,omitempty"`
    ResourceID     string        `json:"resource_id,omitempty"`
}
```

### GraphQL Runner (`pkg/runner/graphql.go`)

**Source:** pkg/runner/graphql.go (lines 34-75)
```go
type GraphQLConfig struct {
    Target          string
    Endpoint        string
    // ... rate limiting, timeout, templates, etc.
}
```

### Execution Flow (`pkg/runner/execution.go`)

**Source:** pkg/runner/execution.go (lines 18-156)
- `executeTemplate()` handles both HTTP and GraphQL
- Calls `executor.Execute(ctx, tmpl, op, authInfo, variables)`
- Variables map already supports dynamic values

---

## Implementation Tasks

### Task 1: Add interactsh Dependency

**Files:**
- Modify: `go.mod`

**Step 1: Add interactsh client dependency**

```bash
go get github.com/projectdiscovery/interactsh/pkg/client
```

**Step 2: Verify dependency added**

Run: `grep interactsh go.mod`
Expected: `github.com/projectdiscovery/interactsh`

**Step 3: Tidy and verify**

```bash
go mod tidy
```

**Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add interactsh client for OOB detection"
```

---

### Task 2: Create OOB Client Package

**Files:**
- Create: `pkg/oob/client.go`
- Create: `pkg/oob/client_test.go`

**Step 1: Write the failing test**

```go
// pkg/oob/client_test.go
package oob

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
    client, err := NewClient(DefaultConfig())
    require.NoError(t, err)
    require.NotNil(t, client)
    defer client.Close()
}

func TestClient_GenerateURL(t *testing.T) {
    client, err := NewClient(DefaultConfig())
    require.NoError(t, err)
    defer client.Close()

    url := client.GenerateURL()
    assert.NotEmpty(t, url)
    assert.Contains(t, url, ".")  // Has subdomain
}

func TestClient_Poll_NoInteraction(t *testing.T) {
    client, err := NewClient(DefaultConfig())
    require.NoError(t, err)
    defer client.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    interactions, err := client.Poll(ctx)
    require.NoError(t, err)
    assert.Empty(t, interactions)  // No interactions yet
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/oob/... -v`
Expected: FAIL - package does not exist

**Step 3: Write minimal implementation**

```go
// pkg/oob/client.go
package oob

import (
    "context"
    "time"

    "github.com/projectdiscovery/interactsh/pkg/client"
)

// Config holds OOB client configuration
type Config struct {
    ServerURL   string        // interactsh server (default: oast.live)
    Token       string        // optional auth token
    PollTimeout time.Duration // how long to poll for interactions
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
    return Config{
        ServerURL:   "oast.live",
        PollTimeout: 10 * time.Second,
    }
}

// Interaction represents an OOB callback received
type Interaction struct {
    Protocol  string    // http, dns, smtp
    URL       string    // full URL that was accessed
    Timestamp time.Time // when interaction occurred
    RemoteIP  string    // source IP
    RawData   string    // raw request data
}

// Client wraps interactsh for OOB detection
type Client struct {
    interactsh *client.Client
    config     Config
}

// NewClient creates a new OOB client
func NewClient(cfg Config) (*Client, error) {
    opts := &client.Options{
        ServerURL: cfg.ServerURL,
        Token:     cfg.Token,
    }

    c, err := client.New(opts)
    if err != nil {
        return nil, err
    }

    return &Client{
        interactsh: c,
        config:     cfg,
    }, nil
}

// GenerateURL returns a unique callback URL for this session
func (c *Client) GenerateURL() string {
    return c.interactsh.URL()
}

// Poll checks for interactions within the timeout period
func (c *Client) Poll(ctx context.Context) ([]Interaction, error) {
    var interactions []Interaction

    // Create polling context with timeout
    pollCtx, cancel := context.WithTimeout(ctx, c.config.PollTimeout)
    defer cancel()

    // Poll for interactions
    c.interactsh.StartPolling(c.config.PollTimeout, func(i *client.Interaction) {
        interactions = append(interactions, Interaction{
            Protocol:  i.Protocol,
            URL:       i.FullId,
            Timestamp: time.Now(),
            RemoteIP:  i.RemoteAddress,
            RawData:   i.RawRequest,
        })
    })

    // Wait for timeout or context cancellation
    <-pollCtx.Done()
    c.interactsh.StopPolling()

    return interactions, nil
}

// Close releases resources
func (c *Client) Close() {
    if c.interactsh != nil {
        c.interactsh.Close()
    }
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./pkg/oob/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/oob/
git commit -m "feat(oob): add interactsh client wrapper"
```

---

### Task 3: Add OOB Support to Template Structures

**Files:**
- Modify: `pkg/templates/template.go`

**Step 1: Write the failing test**

```go
// Add to pkg/templates/template_test.go
func TestTemplate_OOBIndicator(t *testing.T) {
    yamlContent := `
id: oob-test
info:
  name: "OOB Test"
  severity: HIGH
detection:
  success_indicators:
    - type: oob_callback
      protocol: http
`
    tmpl, err := ParseBytes([]byte(yamlContent))
    require.NoError(t, err)
    require.Len(t, tmpl.Detection.SuccessIndicators, 1)
    assert.Equal(t, "oob_callback", tmpl.Detection.SuccessIndicators[0].Type)
    assert.Equal(t, "http", tmpl.Detection.SuccessIndicators[0].Protocol)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/templates/... -run TestTemplate_OOBIndicator -v`
Expected: FAIL - Protocol field doesn't exist

**Step 3: Extend Indicator struct**

```go
// In pkg/templates/template.go, modify Indicator struct:
type Indicator struct {
    Type       string      `yaml:"type,omitempty"`        // status_code, body_field, regex_match, sensitive_fields_exposed, oob_callback
    StatusCode interface{} `yaml:"status_code,omitempty"`
    BodyField  string      `yaml:"body_field,omitempty"`
    Value      interface{} `yaml:"value,omitempty"`
    Pattern    string      `yaml:"pattern,omitempty"`
    Fields     []string    `yaml:"fields,omitempty"`
    Exists     *bool       `yaml:"exists,omitempty"`
    // OOB detection fields
    Protocol   string      `yaml:"protocol,omitempty"`    // http, dns, smtp (for oob_callback)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./pkg/templates/... -run TestTemplate_OOBIndicator -v`
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/templates/template.go pkg/templates/template_test.go
git commit -m "feat(templates): add oob_callback indicator type"
```

---

### Task 4: Implement OOB Variable Substitution in Executor

**Files:**
- Modify: `pkg/templates/execute.go`
- Create: `pkg/templates/execute_oob_test.go`

**Step 1: Write the failing test**

```go
// pkg/templates/execute_oob_test.go
package templates

import (
    "context"
    "testing"

    "github.com/praetorian-inc/hadrian/pkg/oob"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestExecutor_SubstituteInteractsh(t *testing.T) {
    // Create OOB client
    oobClient, err := oob.NewClient(oob.DefaultConfig())
    require.NoError(t, err)
    defer oobClient.Close()

    // Create executor with OOB support
    executor := NewExecutor(nil, "http://example.com", WithOOBClient(oobClient))

    // Template with {{interactsh}} variable
    query := "mutation { importPaste(host: \"{{interactsh}}\") { result } }"

    variables := map[string]string{}
    result := executor.substituteVariables(query, variables)

    assert.NotContains(t, result, "{{interactsh}}")
    assert.Contains(t, result, ".")  // Has interactsh domain
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/templates/... -run TestExecutor_SubstituteInteractsh -v`
Expected: FAIL - WithOOBClient doesn't exist

**Step 3: Add OOB support to Executor**

```go
// In pkg/templates/execute.go

import (
    // ... existing imports
    "github.com/praetorian-inc/hadrian/pkg/oob"
)

// Executor runs test templates against targets
type Executor struct {
    client         HTTPClient
    baseURL        string
    requestTracker *RequestTracker
    oobClient      *oob.Client       // NEW: OOB detection client
    oobURL         string            // NEW: Cached interactsh URL for this session
}

// ExecutorOption configures Executor
type ExecutorOption func(*Executor)

// WithOOBClient enables OOB detection
func WithOOBClient(c *oob.Client) ExecutorOption {
    return func(e *Executor) {
        e.oobClient = c
        if c != nil {
            e.oobURL = c.GenerateURL()
        }
    }
}

// NewExecutor creates an executor with optional OOB support
func NewExecutor(client HTTPClient, baseURL string, opts ...ExecutorOption) *Executor {
    e := &Executor{
        client:         client,
        baseURL:        baseURL,
        requestTracker: NewRequestTracker(),
    }
    for _, opt := range opts {
        opt(e)
    }
    return e
}

// In substituteVariables function, add interactsh handling:
func (e *Executor) substituteVariables(query string, variables map[string]string) string {
    result := query

    // Substitute {{interactsh}} with OOB URL if available
    if e.oobClient != nil && e.oobURL != "" {
        result = strings.ReplaceAll(result, "{{interactsh}}", e.oobURL)
    }

    // Existing variable substitution
    for key, value := range variables {
        result = strings.ReplaceAll(result, "{{"+key+"}}", value)
    }
    return result
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./pkg/templates/... -run TestExecutor_SubstituteInteractsh -v`
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/templates/execute.go pkg/templates/execute_oob_test.go
git commit -m "feat(templates): add interactsh variable substitution"
```

---

### Task 5: Implement OOB Polling in Detection Logic

**Files:**
- Modify: `pkg/templates/execute.go`
- Add to: `pkg/templates/execute_oob_test.go`

**Step 1: Write the failing test**

```go
// Add to pkg/templates/execute_oob_test.go
func TestExecutor_CheckOOBInteraction(t *testing.T) {
    oobClient, err := oob.NewClient(oob.DefaultConfig())
    require.NoError(t, err)
    defer oobClient.Close()

    executor := NewExecutor(nil, "http://example.com", WithOOBClient(oobClient))

    // Indicator requiring OOB callback
    indicator := Indicator{
        Type:     "oob_callback",
        Protocol: "http",
    }

    // No interaction yet
    ctx := context.Background()
    matched, err := executor.checkOOBIndicator(ctx, indicator)
    require.NoError(t, err)
    assert.False(t, matched)  // No callbacks received
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/templates/... -run TestExecutor_CheckOOBInteraction -v`
Expected: FAIL - checkOOBIndicator doesn't exist

**Step 3: Implement OOB indicator checking**

```go
// In pkg/templates/execute.go

// checkOOBIndicator polls for OOB callbacks
func (e *Executor) checkOOBIndicator(ctx context.Context, indicator Indicator) (bool, error) {
    if e.oobClient == nil {
        return false, nil
    }

    interactions, err := e.oobClient.Poll(ctx)
    if err != nil {
        return false, err
    }

    // Check if any interaction matches the required protocol
    for _, interaction := range interactions {
        if indicator.Protocol == "" || interaction.Protocol == indicator.Protocol {
            return true, nil
        }
    }

    return false, nil
}

// Modify checkIndicator to handle oob_callback type:
func (e *Executor) checkIndicator(ctx context.Context, indicator Indicator, resp *http.Response, body []byte) (bool, error) {
    switch indicator.Type {
    case "status_code":
        return e.checkStatusCode(indicator, resp)
    case "body_field":
        return e.checkBodyField(indicator, body)
    case "regex_match":
        return e.checkRegexMatch(indicator, body)
    case "sensitive_fields_exposed":
        return e.checkSensitiveFields(indicator, body)
    case "oob_callback":
        return e.checkOOBIndicator(ctx, indicator)
    default:
        return false, nil
    }
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./pkg/templates/... -run TestExecutor_CheckOOBInteraction -v`
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/templates/execute.go pkg/templates/execute_oob_test.go
git commit -m "feat(templates): add OOB callback detection"
```

---

### Task 6: Add OOB Evidence to Findings

**Files:**
- Modify: `pkg/model/finding.go`
- Create: `pkg/model/finding_test.go` (if not exists)

**Step 1: Write the failing test**

```go
// pkg/model/finding_test.go
package model

import (
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

func TestEvidence_OOBInteraction(t *testing.T) {
    evidence := Evidence{
        OOBInteractions: []OOBInteraction{
            {
                Protocol:  "http",
                URL:       "abc123.oast.live",
                Timestamp: time.Now(),
                RemoteIP:  "1.2.3.4",
            },
        },
    }
    assert.Len(t, evidence.OOBInteractions, 1)
    assert.Equal(t, "http", evidence.OOBInteractions[0].Protocol)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/model/... -run TestEvidence_OOBInteraction -v`
Expected: FAIL - OOBInteractions field doesn't exist

**Step 3: Add OOB fields to Evidence**

```go
// In pkg/model/finding.go

// OOBInteraction represents an out-of-band callback received
type OOBInteraction struct {
    Protocol  string    `json:"protocol"`   // http, dns, smtp
    URL       string    `json:"url"`        // callback URL accessed
    Timestamp time.Time `json:"timestamp"`  // when interaction occurred
    RemoteIP  string    `json:"remote_ip"`  // source IP of callback
    RawData   string    `json:"raw_data,omitempty"` // raw request data
}

type Evidence struct {
    Request  HTTPRequest  `json:"request"`
    Response HTTPResponse `json:"response"`

    // For three-phase mutation tests
    SetupResponse  *HTTPResponse `json:"setup_response,omitempty"`
    AttackResponse *HTTPResponse `json:"attack_response,omitempty"`
    VerifyResponse *HTTPResponse `json:"verify_response,omitempty"`
    ResourceID     string        `json:"resource_id,omitempty"`

    // For OOB detection
    OOBInteractions []OOBInteraction `json:"oob_interactions,omitempty"`
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./pkg/model/... -run TestEvidence_OOBInteraction -v`
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/model/finding.go pkg/model/finding_test.go
git commit -m "feat(model): add OOB interaction evidence fields"
```

---

### Task 7: Integrate OOB Client into GraphQL Runner

**Files:**
- Modify: `pkg/runner/graphql.go`
- Add to: `pkg/runner/graphql_test.go`

**Step 1: Write the failing test**

```go
// Add to pkg/runner/graphql_test.go
func TestGraphQLConfig_OOBEnabled(t *testing.T) {
    config := GraphQLConfig{
        Target:     "http://localhost:5013",
        Endpoint:   "/graphql",
        EnableOOB:  true,
        OOBTimeout: 10,
    }
    assert.True(t, config.EnableOOB)
    assert.Equal(t, 10, config.OOBTimeout)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/runner/... -run TestGraphQLConfig_OOBEnabled -v`
Expected: FAIL - EnableOOB field doesn't exist

**Step 3: Add OOB config to GraphQLConfig**

```go
// In pkg/runner/graphql.go, add to GraphQLConfig struct:

type GraphQLConfig struct {
    // ... existing fields ...

    // OOB detection (optional)
    EnableOOB       bool   // Enable OOB detection for SSRF testing
    OOBServerURL    string // interactsh server (default: oast.live)
    OOBTimeout      int    // Poll timeout in seconds (default: 10)
}

// Add CLI flags in newTestGraphQLCmd():
cmd.Flags().BoolVar(&config.EnableOOB, "enable-oob", false, "Enable out-of-band detection for SSRF testing")
cmd.Flags().StringVar(&config.OOBServerURL, "oob-server", "oast.live", "Interactsh server URL")
cmd.Flags().IntVar(&config.OOBTimeout, "oob-timeout", 10, "OOB poll timeout in seconds")
```

**Step 4: Initialize OOB client in runGraphQLTest**

```go
// In runGraphQLTest function, after HTTP client creation:

var oobClient *oob.Client
if config.EnableOOB {
    oobCfg := oob.Config{
        ServerURL:   config.OOBServerURL,
        PollTimeout: time.Duration(config.OOBTimeout) * time.Second,
    }
    oobClient, err = oob.NewClient(oobCfg)
    if err != nil {
        return fmt.Errorf("failed to create OOB client: %w", err)
    }
    defer oobClient.Close()
    graphqlVerboseLog(config.Verbose, "OOB detection enabled: %s", oobClient.GenerateURL())
}

// Pass to executor creation (in runSecurityChecks):
executor := templates.NewExecutor(rateLimitedClient, endpoint,
    templates.WithOOBClient(oobClient))
```

**Step 5: Run test to verify it passes**

Run: `go test ./pkg/runner/... -run TestGraphQLConfig_OOBEnabled -v`
Expected: PASS

**Step 6: Commit**

```bash
git add pkg/runner/graphql.go pkg/runner/graphql_test.go
git commit -m "feat(runner): integrate OOB client into GraphQL runner"
```

---

### Task 8: Update SSRF Template to Use OOB

**Files:**
- Modify: `testdata/dvga/templates/owasp/api7-ssrf-dvga.yaml`

**Step 1: Update template with {{interactsh}} variable**

```yaml
id: api7-ssrf-dvga
info:
  name: "DVGA - Server-Side Request Forgery via importPaste"
  category: "API7:2023"
  severity: "HIGH"
  author: "hadrian"
  description: "Tests for SSRF vulnerabilities in DVGA's importPaste mutation using OOB detection. The importPaste mutation accepts arbitrary URLs that the server fetches, enabling SSRF attacks."
  tags: ["graphql", "dvga", "ssrf", "oob"]
  requires_llm_triage: false
  test_pattern: "simple"

endpoint_selector:
  requires_auth: false

role_selector:
  attacker_permission_level: "all"
  victim_permission_level: "all"

graphql:
  - query: |
      mutation SSRFExfiltration {
        importPaste(host: "{{interactsh}}", path: "/ssrf-test", port: 80, scheme: "http") {
          result
        }
      }
    matchers:
      - type: status
        status: [200]

detection:
  success_indicators:
    - type: status_code
      status_code: 200
    - type: oob_callback
      protocol: http
  vulnerability_pattern: "dvga_ssrf_import_paste"
```

**Step 2: Test template parsing**

Run: `go test ./pkg/templates/... -run TestParse -v`
Expected: PASS

**Step 3: Commit**

```bash
git add testdata/dvga/templates/owasp/api7-ssrf-dvga.yaml
git commit -m "feat(dvga): update SSRF template to use OOB detection"
```

---

### Task 9: Add REST API OOB Support

**Files:**
- Modify: `pkg/runner/run.go`
- Add to: `pkg/runner/run_test.go`

**Step 1: Write the failing test**

```go
// Add to pkg/runner/run_test.go
func TestRESTConfig_OOBEnabled(t *testing.T) {
    config := Config{
        Target:     "http://localhost:8080",
        EnableOOB:  true,
        OOBTimeout: 15,
    }
    assert.True(t, config.EnableOOB)
    assert.Equal(t, 15, config.OOBTimeout)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/runner/... -run TestRESTConfig_OOBEnabled -v`
Expected: FAIL - EnableOOB field doesn't exist on Config

**Step 3: Add OOB config to REST Config**

```go
// In pkg/runner/run.go or config.go, add to Config struct:

type Config struct {
    // ... existing fields ...

    // OOB detection (optional)
    EnableOOB       bool   // Enable out-of-band detection
    OOBServerURL    string // interactsh server (default: oast.live)
    OOBTimeout      int    // Poll timeout in seconds (default: 10)
}

// Add CLI flags in root command
```

**Step 4: Run test to verify it passes**

Run: `go test ./pkg/runner/... -run TestRESTConfig_OOBEnabled -v`
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/runner/run.go pkg/runner/config.go pkg/runner/run_test.go
git commit -m "feat(runner): add OOB support to REST API runner"
```

---

### Task 10: Integration Test with DVGA

**Files:**
- Create: `pkg/runner/graphql_oob_integration_test.go`

**Step 1: Write integration test**

```go
// pkg/runner/graphql_oob_integration_test.go
//go:build integration

package runner

import (
    "context"
    "os"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestGraphQL_OOB_DVGA_SSRF(t *testing.T) {
    endpoint := os.Getenv("DVGA_ENDPOINT")
    if endpoint == "" {
        t.Skip("DVGA_ENDPOINT not set")
    }

    config := GraphQLConfig{
        Target:        endpoint,
        Endpoint:      "/graphql",
        Templates:     "../../testdata/dvga/templates/owasp",
        TemplateFilters: []string{"api7-ssrf-dvga"},
        EnableOOB:     true,
        OOBTimeout:    15,
        AllowInternal: true,
        Timeout:       30,
        Verbose:       true,
    }

    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    err := runGraphQLTest(ctx, config)
    require.NoError(t, err)
    // Template should execute and OOB detection should trigger (or timeout gracefully)
}
```

**Step 2: Run integration test (manual, requires DVGA)**

Run: `DVGA_ENDPOINT=http://localhost:5013 go test -tags=integration ./pkg/runner/... -run TestGraphQL_OOB_DVGA_SSRF -v`
Expected: PASS (or graceful timeout if no OOB callback)

**Step 3: Commit**

```bash
git add pkg/runner/graphql_oob_integration_test.go
git commit -m "test(runner): add OOB integration test for DVGA SSRF"
```

---

### Task 11: Documentation Update

**Files:**
- Modify: `testdata/dvga/README.md`
- Modify: `README.md` (if OOB section needed)

**Step 1: Update DVGA README**

Add OOB section:

```markdown
### OOB Detection for SSRF Testing

For proper SSRF detection, enable Out-of-Band (OOB) detection:

```bash
./hadrian test graphql \
  --target http://localhost:5013 \
  --templates testdata/dvga/templates/owasp \
  --template api7-ssrf-dvga \
  --enable-oob \
  --oob-timeout 15 \
  --allow-internal \
  --verbose
```

OOB detection uses interactsh to verify that the server actually makes outbound requests.
```

**Step 2: Commit**

```bash
git add testdata/dvga/README.md
git commit -m "docs(dvga): add OOB detection usage instructions"
```

---

## Exit Criteria

This implementation is complete when:

- [ ] 11 tasks implemented with passing tests
- [ ] `go test ./pkg/oob/... -v` passes (3+ tests)
- [ ] `go test ./pkg/templates/... -v` passes (existing + 3 new OOB tests)
- [ ] `go test ./pkg/runner/... -v` passes (existing + 2 new OOB tests)
- [ ] `go test ./pkg/model/... -v` passes (1 new OOB test)
- [ ] `./hadrian test graphql --help` shows `--enable-oob` flag
- [ ] DVGA SSRF template uses `{{interactsh}}` and `oob_callback` indicator
- [ ] Documentation updated in testdata/dvga/README.md

---

## Assumptions

| Assumption | Why Unverified | Risk if Wrong |
|------------|----------------|---------------|
| interactsh client library API is stable | Haven't tested actual library | May need API adjustments |
| oast.live is default interactsh server | Common default, not verified | May need different default |
| Single OOB URL per executor session | Design choice | May need per-request URLs for parallel tests |

---

```json
{
  "agent": "claude",
  "output_type": "implementation-plan",
  "timestamp": "2026-02-03T18:55:24Z",
  "feature_directory": ".claude/.output/plans/2026-02-03-185524-oob-detection",
  "skills_invoked": ["writing-plans", "enforcing-evidence-based-analysis"],
  "library_skills_read": [],
  "source_files_verified": [
    "pkg/templates/template.go:7-186",
    "pkg/templates/execute.go:1-740",
    "pkg/templates/compile.go:1-87",
    "pkg/runner/graphql.go:1-289",
    "pkg/runner/execution.go:1-243",
    "pkg/runner/templates.go:1-45",
    "pkg/model/finding.go:1-72",
    "go.mod:1-32"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Execute plan task-by-task using TDD approach"
  }
}
```
