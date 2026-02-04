package templates

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExecutor_UserProvidedOOBURL tests that user-provided OOB URLs are substituted correctly
func TestExecutor_UserProvidedOOBURL(t *testing.T) {
	userURL := "http://my-callback.example.com/webhook"

	// Create executor with user-provided URL (no OOB client needed)
	executor := NewExecutor(nil, WithUserOOBURL(userURL))

	// Verify user URL is set
	assert.Equal(t, userURL, executor.oobURL)

	// Template with {{interactsh}} placeholder (we'll rename this later)
	query := "mutation { importPaste(host: \"{{interactsh}}\") { result } }"

	// Substitute placeholder with user URL
	result := substituteInteractsh(query, executor.oobURL)

	assert.NotContains(t, result, "{{interactsh}}")
	assert.Contains(t, result, userURL)
}

// TestExecutor_UserOOBURL_NoClient tests that no OOB client is needed with user URL
func TestExecutor_UserOOBURL_NoClient(t *testing.T) {
	userURL := "https://webhook.site/unique-id"

	executor := NewExecutor(nil, WithUserOOBURL(userURL))

	// Should have no OOB client (user handles callbacks themselves)
	assert.Nil(t, executor.oobClient)
	assert.Equal(t, userURL, executor.oobURL)
}
