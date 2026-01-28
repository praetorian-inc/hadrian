package owasp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// hasUnresolvedPlaceholders checks if a path contains unresolved {placeholder} patterns.
// Returns the first unresolved placeholder name if found, or empty string if all resolved.
func hasUnresolvedPlaceholders(path string) string {
	start := strings.Index(path, "{")
	if start == -1 {
		return ""
	}
	end := strings.Index(path[start:], "}")
	if end == -1 {
		return ""
	}
	return path[start+1 : start+end]
}

// HTTPClient interface for making HTTP requests
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// MutationExecutor runs three-phase mutation tests
type MutationExecutor struct {
	httpClient HTTPClient
	tracker    *Tracker
}

// MutationResult contains results from a three-phase mutation test
type MutationResult struct {
	TemplateID    string
	Matched       bool // true if vulnerability found (attack succeeded)
	SetupResponse *model.HTTPResponse
	AttackResponse *model.HTTPResponse
	VerifyResponse *model.HTTPResponse
	ResourceID    string
}

// NewMutationExecutor creates a new mutation executor
func NewMutationExecutor(client HTTPClient) *MutationExecutor {
	return &MutationExecutor{
		httpClient: client,
		tracker:    NewTracker(),
	}
}

// ExecuteMutation runs a three-phase mutation test
func (e *MutationExecutor) ExecuteMutation(
	ctx context.Context,
	tmpl *templates.Template,
	operation string,
	attacker string,
	victim string,
	authTokens map[string]string,
	baseURL string,
) (*MutationResult, error) {
	result := &MutationResult{
		TemplateID: tmpl.ID,
	}

	if tmpl.TestPhases == nil {
		return result, fmt.Errorf("template has no test phases")
	}

	// Phase 1: Setup (create resource)
	if tmpl.TestPhases.Setup != nil {
		setupResp, err := e.executePhase(ctx, baseURL, tmpl.TestPhases.Setup, tmpl.TestPhases.Setup.Auth, authTokens)
		if err != nil {
			return result, fmt.Errorf("setup phase failed: %w", err)
		}
		result.SetupResponse = setupResp

		// Store resource ID if needed - store by field name for later lookup
		if tmpl.TestPhases.Setup.StoreResponseField != "" && setupResp != nil {
			resourceID := extractField(setupResp.Body, tmpl.TestPhases.Setup.StoreResponseField)
			if resourceID != "" {
				result.ResourceID = resourceID
				e.tracker.StoreResource(tmpl.TestPhases.Setup.StoreResponseField, resourceID)
			}
		}
	}

	// Phase 2: Attack (try to access with different role)
	if tmpl.TestPhases.Attack != nil {
		attackResp, err := e.executePhase(ctx, baseURL, tmpl.TestPhases.Attack, tmpl.TestPhases.Attack.Auth, authTokens)
		if err != nil {
			return result, fmt.Errorf("attack phase failed: %w", err)
		}
		result.AttackResponse = attackResp

		// Check if attack succeeded (vulnerability found)
		if matchesDetectionConditions(tmpl.TestPhases.Attack, attackResp.StatusCode, attackResp.Body) {
			result.Matched = true
		}
	}

	// Phase 3: Verify (confirm resource still accessible by victim)
	if tmpl.TestPhases.Verify != nil {
		verifyResp, err := e.executePhase(ctx, baseURL, tmpl.TestPhases.Verify, tmpl.TestPhases.Verify.Auth, authTokens)
		if err != nil {
			return result, fmt.Errorf("verify phase failed: %w", err)
		}
		result.VerifyResponse = verifyResp
	}

	return result, nil
}

// operationToMethod maps CRUD operations to HTTP methods
func operationToMethod(op string) string {
	switch strings.ToLower(op) {
	case "create":
		return http.MethodPost
	case "update":
		return http.MethodPut
	case "delete":
		return http.MethodDelete
	default: // "read" or empty
		return http.MethodGet
	}
}

// executePhase executes a single phase and returns the HTTP response
func (e *MutationExecutor) executePhase(
	ctx context.Context,
	baseURL string,
	phase *templates.Phase,
	authUser string,
	authTokens map[string]string,
) (*model.HTTPResponse, error) {
	if phase == nil {
		return nil, nil
	}

	// Determine HTTP method from operation
	method := operationToMethod(phase.Operation)

	// Build path
	path := phase.Path
	if path == "" {
		return nil, fmt.Errorf("phase path is required")
	}

	// Substitute stored values into path
	if phase.UseStoredField != "" {
		storedValue := e.tracker.GetResource(phase.UseStoredField)
		if storedValue != "" {
			// Replace {fieldName} with stored value
			path = strings.ReplaceAll(path, "{"+phase.UseStoredField+"}", storedValue)
		}
	}

	// Check for unresolved placeholders - error if any remain
	if placeholder := hasUnresolvedPlaceholders(path); placeholder != "" {
		return nil, fmt.Errorf("unresolved placeholder {%s} in path %q - required value not stored from setup phase", placeholder, phase.Path)
	}

	// Build full URL
	url := strings.TrimSuffix(baseURL, "/") + path

	// Build request
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	// Add auth header for the correct user
	// Note: authTokens values already include the scheme prefix (e.g., "Bearer " or "Basic ")
	// from auth.AuthConfig.GetAuth(), so we don't add it here
	if token, ok := authTokens[authUser]; ok && token != "" {
		req.Header.Set("Authorization", token)
	}

	// Execute request
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &model.HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    headerMapFromResponse(resp),
		Body:       string(body),
		Size:       len(body),
	}, nil
}

// extractField extracts a field from JSON response body
// Supports dot notation for nested fields (e.g., "data.id")
// and array indexing (e.g., "items.0.id")
func extractField(body string, fieldPath string) string {
	if fieldPath == "" || body == "" {
		return ""
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return ""
	}

	parts := strings.Split(fieldPath, ".")
	current := interface{}(data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			if val, ok := v[part]; ok {
				current = val
			} else {
				return ""
			}
		case []interface{}:
			// Handle array indexing
			var idx int
			if _, err := fmt.Sscanf(part, "%d", &idx); err != nil {
				return ""
			}
			if idx >= 0 && idx < len(v) {
				current = v[idx]
			} else {
				return ""
			}
		default:
			return ""
		}
	}

	// Convert final value to string
	if current == nil {
		return ""
	}
	if str, ok := current.(string); ok {
		return str
	}
	// Try to convert to string
	switch v := current.(type) {
	case float64:
		return fmt.Sprintf("%v", int(v))
	case bool:
		return fmt.Sprintf("%v", v)
	default:
		b, err := json.Marshal(current)
		if err != nil {
			return ""
		}
		// Remove quotes if it's a string value
		s := string(b)
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
		return s
	}
}

// matchesDetectionConditions checks if a response matches the detection phase criteria
// Returns true if the vulnerability pattern is detected
func matchesDetectionConditions(phase *templates.Phase, statusCode int, body string) bool {
	if phase == nil {
		return false
	}

	// Check status code if specified
	if phase.ExpectedStatus != 0 {
		if statusCode != phase.ExpectedStatus {
			return false
		}
	}

	// Check field value if specified
	if phase.CheckField != "" && phase.ExpectedValue != "" {
		fieldValue := extractField(body, phase.CheckField)
		if fieldValue != phase.ExpectedValue {
			return false
		}
	}

	return true
}

// ClearTracker clears all tracked resources
func (e *MutationExecutor) ClearTracker() {
	e.tracker.Clear()
}

// headerMapFromResponse converts http.Response headers to a simple map
func headerMapFromResponse(resp *http.Response) map[string]string {
	m := make(map[string]string)
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			m[k] = vals[0]
		}
	}
	return m
}

// getMapKeys returns the keys of a map for debugging
func getMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
