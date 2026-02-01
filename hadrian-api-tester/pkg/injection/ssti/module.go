package ssti

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/injection"
	"gopkg.in/yaml.v3"
)

// PayloadFile represents a YAML payload file structure
type PayloadFile struct {
	Engine   string        `yaml:"engine"`
	Payloads []YAMLPayload `yaml:"payloads"`
}

// YAMLPayload represents a single payload in YAML format
type YAMLPayload struct {
	Value       string `yaml:"value"`
	Expected    string `yaml:"expected"`
	Description string `yaml:"description"`
}

// SSTIModule implements injection testing for Server-Side Template Injection
type SSTIModule struct {
	payloads []injection.Payload
}

// NewSSTIModule creates a new SSTI injection testing module with embedded default payloads
func NewSSTIModule() *SSTIModule {
	return &SSTIModule{
		payloads: defaultPayloads(),
	}
}

// NewSSTIModuleWithPayloads creates a new SSTI module with custom payloads loaded from directory
func NewSSTIModuleWithPayloads(payloadDir string) (*SSTIModule, error) {
	payloads, err := LoadPayloadsFromDir(payloadDir)
	if err != nil {
		return nil, fmt.Errorf("loading payloads from %s: %w", payloadDir, err)
	}

	// Fall back to defaults if no payloads loaded from directory
	if len(payloads) == 0 {
		payloads = defaultPayloads()
	}

	return &SSTIModule{
		payloads: payloads,
	}, nil
}

// NewSSTIModuleWithPayloadList creates a new SSTI module with a custom payload list
func NewSSTIModuleWithPayloadList(payloads []injection.Payload) *SSTIModule {
	// Fall back to defaults if no payloads provided
	if len(payloads) == 0 {
		payloads = defaultPayloads()
	}

	return &SSTIModule{
		payloads: payloads,
	}
}

// LoadPayloads is a unified loader that accepts:
// - A directory path (loads all .yaml files in directory)
// - A single file path
// - Comma-separated file paths
func LoadPayloads(path string) ([]injection.Payload, error) {
	// Check if path contains commas (multiple files)
	if strings.Contains(path, ",") {
		files := strings.Split(path, ",")
		return LoadPayloadsFromFiles(files)
	}

	// Check if path is a directory or file
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return LoadPayloadsFromDir(path)
	}

	// Single file
	return LoadPayloadsFromFiles([]string{path})
}

// LoadPayloadsFromFiles loads payloads from one or more YAML files
func LoadPayloadsFromFiles(files []string) ([]injection.Payload, error) {
	var allPayloads []injection.Payload

	for _, file := range files {
		// Trim whitespace from file path
		file = strings.TrimSpace(file)

		// Read and parse YAML file
		payloads, err := loadPayloadFile(file)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", file, err)
		}

		allPayloads = append(allPayloads, payloads...)
	}

	return allPayloads, nil
}

// LoadPayloadsFromDir loads all YAML payload files from a directory
func LoadPayloadsFromDir(dir string) ([]injection.Payload, error) {
	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("directory does not exist: %s", dir)
	}

	// Find all YAML files in directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
	}

	var allPayloads []injection.Payload

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process .yaml and .yml files
		filename := entry.Name()
		ext := filepath.Ext(filename)
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		// Read and parse YAML file
		filePath := filepath.Join(dir, filename)
		payloads, err := loadPayloadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", filename, err)
		}

		allPayloads = append(allPayloads, payloads...)
	}

	return allPayloads, nil
}

// loadPayloadFile loads payloads from a single YAML file
func loadPayloadFile(filePath string) ([]injection.Payload, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var payloadFile PayloadFile
	if err := yaml.Unmarshal(data, &payloadFile); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Convert YAML payloads to injection.Payload format
	payloads := make([]injection.Payload, 0, len(payloadFile.Payloads))
	for _, yp := range payloadFile.Payloads {
		payload := injection.Payload{
			Value:       yp.Value,
			Expected:    yp.Expected,
			Engine:      payloadFile.Engine,
			Description: yp.Description,
		}
		payloads = append(payloads, payload)
	}

	return payloads, nil
}

// Name returns the module name
func (m *SSTIModule) Name() string {
	return "SSTI"
}

// Type returns the injection type
func (m *SSTIModule) Type() injection.InjectionType {
	return injection.InjectionTypeSSTI
}

// Payloads returns the list of SSTI test payloads
func (m *SSTIModule) Payloads() []injection.Payload {
	return m.payloads
}

// Detect analyzes HTTP response for SSTI vulnerabilities
func (m *SSTIModule) Detect(response *http.Response, body string, payload injection.Payload) injection.DetectionResult {
	result := injection.DetectionResult{
		Detected:  false,
		Payload:   payload.Value,
		Evidence:  "",
		MatchType: "",
	}

	// Error-based detection
	if payload.Expected == "error" {
		if m.detectTemplateError(response, body) {
			result.Detected = true
			result.Evidence = body
			result.MatchType = "error"
			return result
		}
	}

	// Exact match detection
	if strings.Contains(body, payload.Expected) {
		result.Detected = true
		result.Evidence = body
		result.MatchType = "exact"
		return result
	}

	return result
}

// detectTemplateError checks for template engine error messages
func (m *SSTIModule) detectTemplateError(response *http.Response, body string) bool {
	// Check for 500 status code
	if response.StatusCode != http.StatusInternalServerError {
		return false
	}

	// Common template error indicators
	errorIndicators := []string{
		"TemplateSyntaxError",
		"TemplateError",
		"TemplateException",
		"template",
		"syntax error",
		"unexpected end of template",
	}

	bodyLower := strings.ToLower(body)
	for _, indicator := range errorIndicators {
		if strings.Contains(bodyLower, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// defaultPayloads returns the default set of SSTI payloads
func defaultPayloads() []injection.Payload {
	return []injection.Payload{
		// Universal - arithmetic operations
		{
			Value:       "{{7*7}}",
			Expected:    "49",
			Engine:      "universal",
			Description: "Universal arithmetic test (Jinja2, Twig)",
		},
		{
			Value:       "${7*7}",
			Expected:    "49",
			Engine:      "universal",
			Description: "Universal arithmetic test (FreeMarker, Velocity)",
		},
		{
			Value:       "<%= 7*7 %>",
			Expected:    "49",
			Engine:      "universal",
			Description: "Universal arithmetic test (ERB)",
		},

		// Jinja2-specific
		{
			Value:       "{{config}}",
			Expected:    "error",
			Engine:      "jinja2",
			Description: "Jinja2 config object access (error-based)",
		},
		{
			Value:       "{{''.__class__}}",
			Expected:    "str",
			Engine:      "jinja2",
			Description: "Jinja2 class introspection",
		},

		// FreeMarker-specific
		{
			Value:       "<#assign x=7*7>${x}",
			Expected:    "49",
			Engine:      "freemarker",
			Description: "FreeMarker variable assignment",
		},
	}
}
