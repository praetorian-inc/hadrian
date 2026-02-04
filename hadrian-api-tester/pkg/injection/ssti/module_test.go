package ssti

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/injection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSTIModule_Name(t *testing.T) {
	module := NewSSTIModule()
	assert.Equal(t, "SSTI", module.Name())
}

func TestSSTIModule_Type(t *testing.T) {
	module := NewSSTIModule()
	assert.Equal(t, injection.InjectionTypeSSTI, module.Type())
}

func TestSSTIModule_Payloads(t *testing.T) {
	module := NewSSTIModule()
	payloads := module.Payloads()

	require.NotEmpty(t, payloads, "SSTI module should have payloads")

	// Verify all payloads are valid
	for _, payload := range payloads {
		assert.True(t, payload.IsValid(), "All payloads should be valid")
	}

	// Verify we have payloads for different engines
	engines := make(map[string]bool)
	for _, payload := range payloads {
		engines[payload.Engine] = true
	}

	assert.True(t, engines["universal"], "Should have universal payloads")
	assert.True(t, engines["jinja2"], "Should have Jinja2 payloads")
	assert.True(t, engines["freemarker"], "Should have FreeMarker payloads")
}

func TestSSTIModule_Detect_ExactMatch(t *testing.T) {
	module := NewSSTIModule()

	// Create response with payload output
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	body := "Result: 49"

	payload := injection.Payload{
		Value:       "{{7*7}}",
		Expected:    "49",
		Engine:      "jinja2",
		Description: "Basic arithmetic",
	}

	result := module.Detect(resp, body, payload)

	assert.True(t, result.Detected, "Should detect SSTI when expected value is in response")
	assert.Equal(t, payload.Value, result.Payload)
	assert.Contains(t, result.Evidence, "49")
	assert.Equal(t, "exact", result.MatchType)
}

func TestSSTIModule_Detect_NoMatch(t *testing.T) {
	module := NewSSTIModule()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	body := "Result: {{7*7}}"

	payload := injection.Payload{
		Value:       "{{7*7}}",
		Expected:    "49",
		Engine:      "jinja2",
		Description: "Basic arithmetic",
	}

	result := module.Detect(resp, body, payload)

	assert.False(t, result.Detected, "Should not detect when payload is not executed")
}

func TestSSTIModule_Detect_ErrorBased(t *testing.T) {
	module := NewSSTIModule()

	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header:     make(http.Header),
	}
	body := "TemplateSyntaxError: unexpected 'end of template'"

	payload := injection.Payload{
		Value:       "{{config}}",
		Expected:    "error",
		Engine:      "jinja2",
		Description: "Error-based detection",
	}

	result := module.Detect(resp, body, payload)

	assert.True(t, result.Detected, "Should detect SSTI from template error")
	assert.Equal(t, "error", result.MatchType)
}

func TestLoadPayloadsFromDir_Success(t *testing.T) {
	// Get the project root directory (2 levels up from this test file)
	// pkg/injection/ssti -> pkg/injection -> pkg -> root
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadDir := filepath.Join(projectRoot, "payloads", "ssti")

	payloads, err := LoadPayloadsFromDir(payloadDir)

	require.NoError(t, err, "Should load payloads from directory without error")
	require.NotEmpty(t, payloads, "Should have loaded payloads")

	// Verify all payloads are valid
	for _, payload := range payloads {
		assert.True(t, payload.IsValid(), "All loaded payloads should be valid")
		assert.NotEmpty(t, payload.Value, "Payload value should not be empty")
		assert.NotEmpty(t, payload.Expected, "Payload expected should not be empty")
		assert.NotEmpty(t, payload.Engine, "Payload engine should not be empty")
		assert.NotEmpty(t, payload.Description, "Payload description should not be empty")
	}

	// Verify we have payloads for different engines
	engines := make(map[string]bool)
	for _, payload := range payloads {
		engines[payload.Engine] = true
	}

	assert.True(t, engines["jinja2"], "Should have Jinja2 payloads")
	assert.True(t, engines["freemarker"], "Should have FreeMarker payloads")
	assert.True(t, engines["twig"], "Should have Twig payloads")
	assert.True(t, engines["erb"], "Should have ERB payloads")

	// Verify minimum payload count (4 engines × 3 payloads = 12)
	assert.GreaterOrEqual(t, len(payloads), 12, "Should have at least 12 payloads from 4 YAML files")
}

func TestLoadPayloadsFromDir_InvalidDirectory(t *testing.T) {
	payloads, err := LoadPayloadsFromDir("/nonexistent/directory")

	assert.Error(t, err, "Should return error for nonexistent directory")
	assert.Nil(t, payloads, "Should return nil payloads on error")
}

func TestLoadPayloadsFromDir_EmptyDirectory(t *testing.T) {
	// Create temporary empty directory
	tmpDir := t.TempDir()

	payloads, err := LoadPayloadsFromDir(tmpDir)

	require.NoError(t, err, "Should not error on empty directory")
	assert.Empty(t, payloads, "Should return empty payload list for directory with no YAML files")
}

func TestLoadPayloadsFromDir_InvalidYAML(t *testing.T) {
	// Create temporary directory with invalid YAML
	tmpDir := t.TempDir()
	invalidYAML := filepath.Join(tmpDir, "invalid.yaml")

	err := os.WriteFile(invalidYAML, []byte("invalid: yaml: content:\n  - this is broken"), 0644)
	require.NoError(t, err)

	payloads, err := LoadPayloadsFromDir(tmpDir)

	assert.Error(t, err, "Should return error for invalid YAML")
	assert.Nil(t, payloads, "Should return nil payloads on YAML parse error")
}

func TestNewSSTIModuleWithPayloads_Success(t *testing.T) {
	// Get the project root directory
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadDir := filepath.Join(projectRoot, "payloads", "ssti")

	module, err := NewSSTIModuleWithPayloads(payloadDir)

	require.NoError(t, err, "Should create module with custom payloads")
	require.NotNil(t, module, "Module should not be nil")

	payloads := module.Payloads()
	assert.NotEmpty(t, payloads, "Module should have payloads")
	assert.Equal(t, "SSTI", module.Name())
	assert.Equal(t, injection.InjectionTypeSSTI, module.Type())
}

func TestNewSSTIModuleWithPayloads_InvalidDirectory(t *testing.T) {
	module, err := NewSSTIModuleWithPayloads("/nonexistent/directory")

	assert.Error(t, err, "Should return error for invalid directory")
	assert.Nil(t, module, "Should return nil module on error")
}

func TestNewSSTIModule_BackwardCompatibility(t *testing.T) {
	// Verify that NewSSTIModule() still works with embedded defaults
	module := NewSSTIModule()

	require.NotNil(t, module, "Module should not be nil")
	payloads := module.Payloads()
	assert.NotEmpty(t, payloads, "Should have embedded default payloads")

	// Verify structure hasn't changed
	assert.Equal(t, "SSTI", module.Name())
	assert.Equal(t, injection.InjectionTypeSSTI, module.Type())
}

func TestLoadPayloadsFromFiles_SingleFile(t *testing.T) {
	// Get the project root and a single payload file
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	singleFile := filepath.Join(projectRoot, "payloads", "ssti", "jinja2.yaml")

	files := []string{singleFile}
	payloads, err := LoadPayloadsFromFiles(files)

	require.NoError(t, err, "Should load payloads from single file")
	require.NotEmpty(t, payloads, "Should have loaded payloads from jinja2.yaml")

	// Verify all payloads are from jinja2
	for _, payload := range payloads {
		assert.Equal(t, "jinja2", payload.Engine, "All payloads should be from jinja2 engine")
		assert.True(t, payload.IsValid(), "All payloads should be valid")
	}
}

func TestLoadPayloadsFromFiles_MultipleFiles(t *testing.T) {
	// Get the project root
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadDir := filepath.Join(projectRoot, "payloads", "ssti")

	files := []string{
		filepath.Join(payloadDir, "jinja2.yaml"),
		filepath.Join(payloadDir, "twig.yaml"),
	}

	payloads, err := LoadPayloadsFromFiles(files)

	require.NoError(t, err, "Should load payloads from multiple files")
	require.NotEmpty(t, payloads, "Should have loaded payloads")

	// Verify we have payloads from both engines
	engines := make(map[string]bool)
	for _, payload := range payloads {
		engines[payload.Engine] = true
	}

	assert.True(t, engines["jinja2"], "Should have jinja2 payloads")
	assert.True(t, engines["twig"], "Should have twig payloads")
}

func TestLoadPayloadsFromFiles_WithWhitespace(t *testing.T) {
	// Test that whitespace is trimmed from file paths
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadDir := filepath.Join(projectRoot, "payloads", "ssti")

	files := []string{
		"  " + filepath.Join(payloadDir, "jinja2.yaml") + "  ", // with whitespace
	}

	payloads, err := LoadPayloadsFromFiles(files)

	require.NoError(t, err, "Should handle whitespace in file paths")
	require.NotEmpty(t, payloads, "Should have loaded payloads")
}

func TestLoadPayloadsFromFiles_InvalidFile(t *testing.T) {
	files := []string{"/nonexistent/file.yaml"}

	payloads, err := LoadPayloadsFromFiles(files)

	assert.Error(t, err, "Should return error for nonexistent file")
	assert.Nil(t, payloads, "Should return nil payloads on error")
}

func TestLoadPayloads_SingleFile(t *testing.T) {
	// Test unified loader with single file
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	singleFile := filepath.Join(projectRoot, "payloads", "ssti", "jinja2.yaml")

	payloads, err := LoadPayloads(singleFile)

	require.NoError(t, err, "Should load payloads from single file")
	require.NotEmpty(t, payloads, "Should have loaded payloads")

	// Verify all are jinja2
	for _, payload := range payloads {
		assert.Equal(t, "jinja2", payload.Engine)
	}
}

func TestLoadPayloads_MultipleFiles(t *testing.T) {
	// Test unified loader with comma-separated files
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadDir := filepath.Join(projectRoot, "payloads", "ssti")

	path := filepath.Join(payloadDir, "jinja2.yaml") + "," + filepath.Join(payloadDir, "twig.yaml")

	payloads, err := LoadPayloads(path)

	require.NoError(t, err, "Should load payloads from comma-separated files")
	require.NotEmpty(t, payloads, "Should have loaded payloads")

	// Verify we have both engines
	engines := make(map[string]bool)
	for _, payload := range payloads {
		engines[payload.Engine] = true
	}

	assert.True(t, engines["jinja2"], "Should have jinja2 payloads")
	assert.True(t, engines["twig"], "Should have twig payloads")
}

func TestLoadPayloads_Directory(t *testing.T) {
	// Test unified loader with directory (backward compatibility)
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadDir := filepath.Join(projectRoot, "payloads", "ssti")

	payloads, err := LoadPayloads(payloadDir)

	require.NoError(t, err, "Should load payloads from directory")
	require.NotEmpty(t, payloads, "Should have loaded payloads")

	// Should have multiple engines
	engines := make(map[string]bool)
	for _, payload := range payloads {
		engines[payload.Engine] = true
	}

	assert.GreaterOrEqual(t, len(engines), 3, "Should have at least 3 different engines")
}

// ============================================================================
// NEW TEMPLATE ENGINE TESTS - TDD RED PHASE
// These tests verify support for additional template engines beyond the original 4
// ============================================================================

func TestLoadPayloadsFromDir_AllEngines(t *testing.T) {
	// This test verifies that ALL supported template engines have payload files
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadDir := filepath.Join(projectRoot, "payloads", "ssti")

	payloads, err := LoadPayloadsFromDir(payloadDir)
	require.NoError(t, err, "Should load payloads from directory without error")

	// Collect all engines
	engines := make(map[string]int)
	for _, payload := range payloads {
		engines[payload.Engine]++
	}

	// Original engines (4)
	assert.True(t, engines["jinja2"] > 0, "Should have Jinja2 payloads")
	assert.True(t, engines["freemarker"] > 0, "Should have FreeMarker payloads")
	assert.True(t, engines["twig"] > 0, "Should have Twig payloads")
	assert.True(t, engines["erb"] > 0, "Should have ERB payloads")

	// New engines (8 additional)
	assert.True(t, engines["velocity"] > 0, "Should have Velocity payloads (Java/Apache)")
	assert.True(t, engines["pebble"] > 0, "Should have Pebble payloads (Java)")
	assert.True(t, engines["thymeleaf"] > 0, "Should have Thymeleaf payloads (Spring Boot)")
	assert.True(t, engines["smarty"] > 0, "Should have Smarty payloads (PHP)")
	assert.True(t, engines["mako"] > 0, "Should have Mako payloads (Python)")
	assert.True(t, engines["handlebars"] > 0, "Should have Handlebars payloads (Node.js)")
	assert.True(t, engines["pug"] > 0, "Should have Pug/Jade payloads (Node.js)")
	assert.True(t, engines["razor"] > 0, "Should have Razor payloads (ASP.NET)")

	// Total: 12 engines
	assert.GreaterOrEqual(t, len(engines), 12, "Should have at least 12 different template engines")
}

func TestVelocityPayloads_VerificationChain(t *testing.T) {
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadFile := filepath.Join(projectRoot, "payloads", "ssti", "velocity.yaml")

	payloadFileData, err := LoadPayloadFileWithPayloads(payloadFile)
	require.NoError(t, err, "Should load velocity.yaml")
	require.Equal(t, "velocity", payloadFileData.Engine)
	require.Len(t, payloadFileData.Payloads, 3, "Velocity should have 3-pass verification chain")

	// Verify arithmetic payloads use ${} syntax
	assert.Contains(t, payloadFileData.Payloads[0].Value, "$", "Velocity uses $ syntax")
	assert.Equal(t, "1337", payloadFileData.Payloads[0].Expected)
	assert.Equal(t, "481", payloadFileData.Payloads[1].Expected)
	assert.Equal(t, "1513", payloadFileData.Payloads[2].Expected)
}

func TestPebblePayloads_VerificationChain(t *testing.T) {
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadFile := filepath.Join(projectRoot, "payloads", "ssti", "pebble.yaml")

	payloadFileData, err := LoadPayloadFileWithPayloads(payloadFile)
	require.NoError(t, err, "Should load pebble.yaml")
	require.Equal(t, "pebble", payloadFileData.Engine)
	require.Len(t, payloadFileData.Payloads, 3, "Pebble should have 3-pass verification chain")

	// Verify arithmetic payloads use {{ }} syntax
	assert.Contains(t, payloadFileData.Payloads[0].Value, "{{", "Pebble uses {{ }} syntax")
	assert.Equal(t, "1337", payloadFileData.Payloads[0].Expected)
	assert.Equal(t, "481", payloadFileData.Payloads[1].Expected)
	assert.Equal(t, "1513", payloadFileData.Payloads[2].Expected)
}

func TestThymeleafPayloads_VerificationChain(t *testing.T) {
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadFile := filepath.Join(projectRoot, "payloads", "ssti", "thymeleaf.yaml")

	payloadFileData, err := LoadPayloadFileWithPayloads(payloadFile)
	require.NoError(t, err, "Should load thymeleaf.yaml")
	require.Equal(t, "thymeleaf", payloadFileData.Engine)
	require.Len(t, payloadFileData.Payloads, 3, "Thymeleaf should have 3-pass verification chain")

	// Verify payloads use Thymeleaf syntax [[${...}]] or __${...}__
	firstPayload := payloadFileData.Payloads[0].Value
	hasThymeleafSyntax := strings.Contains(firstPayload, "[[${") || strings.Contains(firstPayload, "__${") || strings.Contains(firstPayload, "${")
	assert.True(t, hasThymeleafSyntax, "Thymeleaf uses [[${...}]], __${...}__, or ${...} syntax")
	assert.Equal(t, "1337", payloadFileData.Payloads[0].Expected)
	assert.Equal(t, "481", payloadFileData.Payloads[1].Expected)
	assert.Equal(t, "1513", payloadFileData.Payloads[2].Expected)
}

func TestSmartyPayloads_VerificationChain(t *testing.T) {
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadFile := filepath.Join(projectRoot, "payloads", "ssti", "smarty.yaml")

	payloadFileData, err := LoadPayloadFileWithPayloads(payloadFile)
	require.NoError(t, err, "Should load smarty.yaml")
	require.Equal(t, "smarty", payloadFileData.Engine)
	require.Len(t, payloadFileData.Payloads, 3, "Smarty should have 3-pass verification chain")

	// Verify payloads use Smarty {math} or {$...} syntax
	firstPayload := payloadFileData.Payloads[0].Value
	hasSmartyMath := strings.Contains(firstPayload, "{math") || strings.Contains(firstPayload, "{$")
	assert.True(t, hasSmartyMath, "Smarty uses {math} or {$...} syntax")
	assert.Equal(t, "1337", payloadFileData.Payloads[0].Expected)
	assert.Equal(t, "481", payloadFileData.Payloads[1].Expected)
	assert.Equal(t, "1513", payloadFileData.Payloads[2].Expected)
}

func TestMakoPayloads_VerificationChain(t *testing.T) {
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadFile := filepath.Join(projectRoot, "payloads", "ssti", "mako.yaml")

	payloadFileData, err := LoadPayloadFileWithPayloads(payloadFile)
	require.NoError(t, err, "Should load mako.yaml")
	require.Equal(t, "mako", payloadFileData.Engine)
	require.Len(t, payloadFileData.Payloads, 3, "Mako should have 3-pass verification chain")

	// Verify payloads use Mako ${...} syntax
	assert.Contains(t, payloadFileData.Payloads[0].Value, "${", "Mako uses ${...} syntax")
	assert.Equal(t, "1337", payloadFileData.Payloads[0].Expected)
	assert.Equal(t, "481", payloadFileData.Payloads[1].Expected)
	assert.Equal(t, "1513", payloadFileData.Payloads[2].Expected)
}

func TestHandlebarsPayloads_VerificationChain(t *testing.T) {
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadFile := filepath.Join(projectRoot, "payloads", "ssti", "handlebars.yaml")

	payloadFileData, err := LoadPayloadFileWithPayloads(payloadFile)
	require.NoError(t, err, "Should load handlebars.yaml")
	require.Equal(t, "handlebars", payloadFileData.Engine)
	require.Len(t, payloadFileData.Payloads, 3, "Handlebars should have 3-pass verification chain")

	// Verify payloads use Handlebars {{...}} syntax
	assert.Contains(t, payloadFileData.Payloads[0].Value, "{{", "Handlebars uses {{...}} syntax")
	assert.Equal(t, "1337", payloadFileData.Payloads[0].Expected)
	assert.Equal(t, "481", payloadFileData.Payloads[1].Expected)
	assert.Equal(t, "1513", payloadFileData.Payloads[2].Expected)
}

func TestPugPayloads_VerificationChain(t *testing.T) {
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadFile := filepath.Join(projectRoot, "payloads", "ssti", "pug.yaml")

	payloadFileData, err := LoadPayloadFileWithPayloads(payloadFile)
	require.NoError(t, err, "Should load pug.yaml")
	require.Equal(t, "pug", payloadFileData.Engine)
	require.Len(t, payloadFileData.Payloads, 3, "Pug should have 3-pass verification chain")

	// Verify payloads use Pug #{...} or = syntax
	firstPayload := payloadFileData.Payloads[0].Value
	hasPugSyntax := strings.Contains(firstPayload, "#{") || strings.Contains(firstPayload, "=")
	assert.True(t, hasPugSyntax, "Pug uses #{...} or = syntax")
	assert.Equal(t, "1337", payloadFileData.Payloads[0].Expected)
	assert.Equal(t, "481", payloadFileData.Payloads[1].Expected)
	assert.Equal(t, "1513", payloadFileData.Payloads[2].Expected)
}

func TestRazorPayloads_VerificationChain(t *testing.T) {
	testDir, err := os.Getwd()
	require.NoError(t, err)

	projectRoot := filepath.Join(testDir, "..", "..", "..")
	payloadFile := filepath.Join(projectRoot, "payloads", "ssti", "razor.yaml")

	payloadFileData, err := LoadPayloadFileWithPayloads(payloadFile)
	require.NoError(t, err, "Should load razor.yaml")
	require.Equal(t, "razor", payloadFileData.Engine)
	require.Len(t, payloadFileData.Payloads, 3, "Razor should have 3-pass verification chain")

	// Verify payloads use Razor @(...) syntax
	assert.Contains(t, payloadFileData.Payloads[0].Value, "@", "Razor uses @(...) syntax")
	assert.Equal(t, "1337", payloadFileData.Payloads[0].Expected)
	assert.Equal(t, "481", payloadFileData.Payloads[1].Expected)
	assert.Equal(t, "1513", payloadFileData.Payloads[2].Expected)
}

func TestNewEnginesDetection_Velocity(t *testing.T) {
	module := NewSSTIModule()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	body := "Result: 1337"

	payload := injection.Payload{
		Value:       "${7*191}",
		Expected:    "1337",
		Engine:      "velocity",
		Description: "Velocity arithmetic test",
	}

	result := module.Detect(resp, body, payload)

	assert.True(t, result.Detected, "Should detect Velocity SSTI when expected value is in response")
	assert.Equal(t, "exact", result.MatchType)
}

func TestNewEnginesDetection_Thymeleaf(t *testing.T) {
	module := NewSSTIModule()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	body := "Result: 1337"

	payload := injection.Payload{
		Value:       "${7*191}",
		Expected:    "1337",
		Engine:      "thymeleaf",
		Description: "Thymeleaf arithmetic test",
	}

	result := module.Detect(resp, body, payload)

	assert.True(t, result.Detected, "Should detect Thymeleaf SSTI when expected value is in response")
	assert.Equal(t, "exact", result.MatchType)
}

func TestNewEnginesDetection_Razor(t *testing.T) {
	module := NewSSTIModule()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	body := "Result: 1337"

	payload := injection.Payload{
		Value:       "@(7*191)",
		Expected:    "1337",
		Engine:      "razor",
		Description: "Razor arithmetic test",
	}

	result := module.Detect(resp, body, payload)

	assert.True(t, result.Detected, "Should detect Razor SSTI when expected value is in response")
	assert.Equal(t, "exact", result.MatchType)
}
