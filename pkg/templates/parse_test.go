package templates

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestParse_ValidTemplate(t *testing.T) {
	tmpl, err := Parse("testdata/valid-template.yaml")
	require.NoError(t, err)
	require.NotNil(t, tmpl)

	assert.Equal(t, "test-template", tmpl.ID)
	assert.Equal(t, "Test Template", tmpl.Info.Name)
	assert.Equal(t, "TEST", tmpl.Info.Category)
	assert.Equal(t, "HIGH", tmpl.Info.Severity)
	assert.Equal(t, "Hadrian", tmpl.Info.Author)
	assert.Equal(t, []string{"test"}, tmpl.Info.Tags)
	assert.False(t, tmpl.Info.RequiresLLMTriage)
	assert.Equal(t, "simple", tmpl.Info.TestPattern)

	assert.True(t, tmpl.EndpointSelector.HasPathParameter)
	assert.True(t, tmpl.EndpointSelector.RequiresAuth)
	assert.Equal(t, []string{"GET"}, tmpl.EndpointSelector.Methods)

	assert.Equal(t, "lower", tmpl.RoleSelector.AttackerPermissionLevel)
	assert.Equal(t, "higher", tmpl.RoleSelector.VictimPermissionLevel)

	require.Len(t, tmpl.HTTP, 1)
	assert.Equal(t, "GET", tmpl.HTTP[0].Method)
	assert.Equal(t, "/test", tmpl.HTTP[0].Path)

	require.Len(t, tmpl.HTTP[0].Matchers, 1)
	assert.Equal(t, "status", tmpl.HTTP[0].Matchers[0].Type)
	assert.Equal(t, []int{200}, tmpl.HTTP[0].Matchers[0].Status)

	require.Len(t, tmpl.Detection.SuccessIndicators, 1)
	assert.Equal(t, "status_code", tmpl.Detection.SuccessIndicators[0].Type)
	assert.Equal(t, 200, tmpl.Detection.SuccessIndicators[0].StatusCode)
	assert.Equal(t, "test", tmpl.Detection.VulnerabilityPattern)
}

func TestParse_FileNotFound(t *testing.T) {
	_, err := Parse("testdata/nonexistent.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stat template file")
}

func TestParse_FileTooLarge(t *testing.T) {
	// Create a large file (>1MB)
	tmpFile, err := os.CreateTemp("", "large-*.yaml")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// Write > 1MB
	data := make([]byte, MaxYAMLSize+1)
	_, err = tmpFile.Write(data)
	require.NoError(t, err)
	_ = tmpFile.Close()

	_, err = Parse(tmpFile.Name())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template file too large")
}

func TestParseYAML_ValidYAML(t *testing.T) {
	yamlData := `
id: simple-test
info:
  name: "Simple Test"
  category: "AUTH"
  severity: "MEDIUM"
  author: "Test"
  tags: []
  requires_llm_triage: false
  test_pattern: "simple"

endpoint_selector:
  has_path_parameter: false
  requires_auth: false
  methods: ["POST"]

role_selector:
  attacker_permission_level: "all"
  victim_permission_level: "all"

http:
  - method: "POST"
    path: "/login"
    matchers:
      - type: word
        words: ["success"]

detection:
  success_indicators:
    - type: body_field
      body_field: "token"
      exists: true
  vulnerability_pattern: "authentication bypass"
`
	tmpl, err := ParseYAML([]byte(yamlData))
	require.NoError(t, err)
	require.NotNil(t, tmpl)

	assert.Equal(t, "simple-test", tmpl.ID)
	assert.Equal(t, "Simple Test", tmpl.Info.Name)
}

func TestParseYAML_InvalidYAML(t *testing.T) {
	invalidYAML := `
id: test
info:
  name: unclosed string
  invalid: [ broken
`
	_, err := ParseYAML([]byte(invalidYAML))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "YAML parse error")
}

func TestParseYAML_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		errorMsg string
	}{
		{
			name: "missing id",
			yaml: `
info:
  name: "Test"
  category: "TEST"
`,
			errorMsg: "template missing required field: id",
		},
		{
			name: "missing info.name",
			yaml: `
id: test
info:
  category: "TEST"
`,
			errorMsg: "template missing required field: info.name",
		},
		{
			name: "missing info.category",
			yaml: `
id: test
info:
  name: "Test"
`,
			errorMsg: "template missing required field: info.category",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseYAML([]byte(tt.yaml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

func TestParseYAML_UnknownFields(t *testing.T) {
	yamlWithUnknown := `
id: test
info:
  name: "Test"
  category: "TEST"
  severity: "LOW"
  author: "Test"
  tags: []
  requires_llm_triage: false
  test_pattern: "simple"
  unknown_field: "should error"

endpoint_selector:
  has_path_parameter: false
  requires_auth: false
  methods: ["GET"]

role_selector:
  attacker_permission_level: "all"
  victim_permission_level: "all"

http: []

detection:
  success_indicators: []
  vulnerability_pattern: "test"
`
	_, err := ParseYAML([]byte(yamlWithUnknown))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown_field")
}

func TestValidateTemplate_Success(t *testing.T) {
	tmpl := &Template{
		ID: "test",
		Info: TemplateInfo{
			Name:     "Test",
			Category: "TEST",
		},
	}

	err := validateTemplate(tmpl)
	assert.NoError(t, err)
}

func TestValidateTemplate_MissingID(t *testing.T) {
	tmpl := &Template{
		Info: TemplateInfo{
			Name:     "Test",
			Category: "TEST",
		},
	}

	err := validateTemplate(tmpl)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template missing required field: id")
}

func TestValidateTemplate_MissingName(t *testing.T) {
	tmpl := &Template{
		ID: "test",
		Info: TemplateInfo{
			Category: "TEST",
		},
	}

	err := validateTemplate(tmpl)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template missing required field: info.name")
}

func TestValidateTemplate_MissingCategory(t *testing.T) {
	tmpl := &Template{
		ID: "test",
		Info: TemplateInfo{
			Name: "Test",
		},
	}

	err := validateTemplate(tmpl)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template missing required field: info.category")
}

func TestContainsDangerousFunction_Detected(t *testing.T) {
	dangerousCases := []string{
		"system('rm -rf /')",
		"exec('malicious')",
		"eval(userInput)",
		"os.system('bad')",
		"cmd.run('evil')",
		"shell('danger')",
		"import os",
		"require('fs')",
		"load('file')",
		"__import__('module')",
	}

	for _, expr := range dangerousCases {
		t.Run(expr, func(t *testing.T) {
			assert.True(t, containsDangerousFunction(expr), "Should detect dangerous function in: %s", expr)
		})
	}
}

func TestContainsDangerousFunction_Safe(t *testing.T) {
	safeCases := []string{
		"status_code == 200",
		"len(body) > 0",
		"contains(response, 'success')",
		"regex('pattern', text)",
		"md5(data)",
	}

	for _, expr := range safeCases {
		t.Run(expr, func(t *testing.T) {
			assert.False(t, containsDangerousFunction(expr), "Should NOT detect dangerous function in: %s", expr)
		})
	}
}

func TestSetupPhases_UnmarshalYAML_SinglePhase(t *testing.T) {
	// Test backwards compatibility: single setup phase (object syntax)
	yamlData := `
test_phases:
  setup:
    path: "/api/dashboard"
    auth: "victim"
    store_response_field: "video_id"
  attack:
    path: "/api/videos/{video_id}"
    operation: "read"
    auth: "attacker"
`
	var tmpl struct {
		TestPhases *TestPhases `yaml:"test_phases"`
	}

	// Parse just the test_phases for direct testing
	yamlBytes := []byte(yamlData)
	err := yaml.Unmarshal(yamlBytes, &tmpl)
	require.NoError(t, err)
	require.NotNil(t, tmpl.TestPhases)

	// Verify single setup phase is wrapped in a slice
	require.Len(t, tmpl.TestPhases.Setup, 1)
	assert.Equal(t, "/api/dashboard", tmpl.TestPhases.Setup[0].Path)
	assert.Equal(t, "victim", tmpl.TestPhases.Setup[0].Auth)
	assert.Equal(t, "video_id", tmpl.TestPhases.Setup[0].StoreResponseField)
}

func TestSetupPhases_UnmarshalYAML_MultiplePhases(t *testing.T) {
	// Test new array syntax: multiple setup phases
	yamlData := `
test_phases:
  setup:
    - path: "/api/dashboard"
      auth: "attacker"
      store_response_fields:
        attacker_video_id: "video_id"
    - path: "/api/dashboard"
      auth: "victim"
      store_response_fields:
        victim_video_id: "video_id"
  attack:
    path: "/api/videos/{attacker_video_id}"
    operation: "update"
    auth: "attacker"
`
	var tmpl struct {
		TestPhases *TestPhases `yaml:"test_phases"`
	}

	yamlBytes := []byte(yamlData)
	err := yaml.Unmarshal(yamlBytes, &tmpl)
	require.NoError(t, err)
	require.NotNil(t, tmpl.TestPhases)

	// Verify multiple setup phases
	require.Len(t, tmpl.TestPhases.Setup, 2)

	// First setup phase
	assert.Equal(t, "/api/dashboard", tmpl.TestPhases.Setup[0].Path)
	assert.Equal(t, "attacker", tmpl.TestPhases.Setup[0].Auth)
	require.NotNil(t, tmpl.TestPhases.Setup[0].StoreResponseFields)
	assert.Equal(t, "video_id", tmpl.TestPhases.Setup[0].StoreResponseFields["attacker_video_id"])

	// Second setup phase
	assert.Equal(t, "/api/dashboard", tmpl.TestPhases.Setup[1].Path)
	assert.Equal(t, "victim", tmpl.TestPhases.Setup[1].Auth)
	require.NotNil(t, tmpl.TestPhases.Setup[1].StoreResponseFields)
	assert.Equal(t, "video_id", tmpl.TestPhases.Setup[1].StoreResponseFields["victim_video_id"])
}

func TestValidateTemplate_RejectsDSLMatchers(t *testing.T) {
	tests := []struct {
		name         string
		templateID   string
		testIndex    int
		matcherIndex int
	}{
		{
			name:         "single DSL matcher",
			templateID:   "test-template-1",
			testIndex:    0,
			matcherIndex: 0,
		},
		{
			name:         "DSL in second matcher",
			templateID:   "test-template-2",
			testIndex:    0,
			matcherIndex: 1,
		},
		{
			name:         "DSL in second test",
			templateID:   "test-template-3",
			testIndex:    1,
			matcherIndex: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &Template{
				ID: tt.templateID,
				Info: TemplateInfo{
					Name:     "Test",
					Category: "TEST",
				},
				HTTP: []HTTPTest{
					{
						Method: "GET",
						Path:   "/test",
						Matchers: []Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			}

			// Add additional test if needed
			if tt.testIndex == 1 {
				tmpl.HTTP = append(tmpl.HTTP, HTTPTest{
					Method:   "POST",
					Path:     "/test2",
					Matchers: []Matcher{},
				})
			}

			// Add additional matcher if needed
			if tt.matcherIndex == 1 {
				tmpl.HTTP[tt.testIndex].Matchers = append(tmpl.HTTP[tt.testIndex].Matchers, Matcher{Type: "word", Words: []string{"test"}})
			}

			// Insert DSL matcher at specified position
			dslMatcher := Matcher{Type: "dsl"}
			tmpl.HTTP[tt.testIndex].Matchers = append(
				tmpl.HTTP[tt.testIndex].Matchers[:tt.matcherIndex],
				append([]Matcher{dslMatcher}, tmpl.HTTP[tt.testIndex].Matchers[tt.matcherIndex:]...)...,
			)

			err := validateTemplate(tmpl)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "DSL matchers are not supported")
			assert.Contains(t, err.Error(), tt.templateID)
			assert.Contains(t, err.Error(), fmt.Sprintf("test %d", tt.testIndex+1))
			assert.Contains(t, err.Error(), fmt.Sprintf("matcher %d", tt.matcherIndex+1))
		})
	}
}
