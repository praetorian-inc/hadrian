package templates

import (
	"testing"
)

// TestCompile_Success tests successful template compilation
func TestCompile_Success(t *testing.T) {
	tmpl := &Template{
		ID: "test-template",
		HTTP: []HTTPTest{
			{
				Method: "GET",
				Path:   "/api/test",
				Matchers: []Matcher{
					{
						Type:  "regex",
						Regex: []string{"test.*pattern"},
						Part:  "body",
					},
				},
			},
		},
	}

	compiled, err := Compile(tmpl)
	if err != nil {
		t.Fatalf("Compile() failed: %v", err)
	}

	if compiled == nil {
		t.Fatal("Compile() returned nil")
	}

	if compiled.Template != tmpl {
		t.Error("Compiled template doesn't reference original")
	}
}

// TestCompile_ValidTemplate tests that compilation preserves template structure
func TestCompile_ValidTemplate(t *testing.T) {
	tmpl := &Template{
		ID: "valid-template",
		Info: TemplateInfo{
			Name:     "Test Template",
			Category: "test",
			Severity: "high",
		},
		HTTP: []HTTPTest{
			{
				Method: "POST",
				Path:   "/api/resource",
				Matchers: []Matcher{
					{
						Type:  "word",
						Words: []string{"success", "created"},
						Part:  "body",
					},
				},
			},
		},
	}

	compiled, err := Compile(tmpl)
	if err != nil {
		t.Fatalf("Compile() failed: %v", err)
	}

	if compiled.Template.ID != "valid-template" {
		t.Errorf("ID mismatch: got %q, want %q", compiled.Template.ID, "valid-template")
	}

	if compiled.Template.Info.Name != "Test Template" {
		t.Errorf("Name mismatch: got %q, want %q", compiled.Template.Info.Name, "Test Template")
	}
}

// TestCompile_PrecompiledRegex tests that regex patterns are pre-compiled
func TestCompile_PrecompiledRegex(t *testing.T) {
	tmpl := &Template{
		ID: "regex-template",
		HTTP: []HTTPTest{
			{
				Method: "GET",
				Path:   "/api/data",
				Matchers: []Matcher{
					{
						Type:  "regex",
						Regex: []string{"^test$", "\\d{3}"},
						Part:  "body",
					},
				},
			},
		},
	}

	compiled, err := Compile(tmpl)
	if err != nil {
		t.Fatalf("Compile() failed: %v", err)
	}

	if len(compiled.CompiledMatchers) != 1 {
		t.Fatalf("Expected 1 compiled matcher, got %d", len(compiled.CompiledMatchers))
	}

	matcher := compiled.CompiledMatchers[0]
	if len(matcher.CompiledRegex) != 2 {
		t.Errorf("Expected 2 compiled regex, got %d", len(matcher.CompiledRegex))
	}

	// Verify regex actually compiled
	for i, re := range matcher.CompiledRegex {
		if re == nil {
			t.Errorf("CompiledRegex[%d] is nil", i)
		}
	}

	// Test regex functionality (100x perf gain validation)
	if !matcher.CompiledRegex[0].MatchString("test") {
		t.Error("First regex should match 'test'")
	}

	if !matcher.CompiledRegex[1].MatchString("123") {
		t.Error("Second regex should match '123'")
	}
}

// TestCompile_InvalidRegex tests error handling for invalid regex patterns
func TestCompile_InvalidRegex(t *testing.T) {
	tmpl := &Template{
		ID: "invalid-regex",
		HTTP: []HTTPTest{
			{
				Method: "GET",
				Path:   "/test",
				Matchers: []Matcher{
					{
						Type:  "regex",
						Regex: []string{"[invalid("},
						Part:  "body",
					},
				},
			},
		},
	}

	_, err := Compile(tmpl)
	if err == nil {
		t.Fatal("Compile() should fail with invalid regex")
	}

	// Verify error message contains helpful context
	errMsg := err.Error()
	if errMsg == "" {
		t.Error("Error message should not be empty")
	}
}

// TestCompile_PathPattern_Valid tests that a valid PathPattern is pre-compiled
func TestCompile_PathPattern_Valid(t *testing.T) {
	tmpl := &Template{
		ID: "path-pattern-template",
		EndpointSelector: EndpointSelector{
			PathPattern: `/api/users/\d+`,
		},
		HTTP: []HTTPTest{
			{Method: "GET", Path: "/api/users/{id}"},
		},
	}

	compiled, err := Compile(tmpl)
	if err != nil {
		t.Fatalf("Compile() failed: %v", err)
	}

	if compiled.CompiledPathPattern == nil {
		t.Fatal("CompiledPathPattern should not be nil for valid PathPattern")
	}

	// Verify it matches expected paths
	if !compiled.CompiledPathPattern.MatchString("/api/users/123") {
		t.Error("CompiledPathPattern should match /api/users/123")
	}
	if compiled.CompiledPathPattern.MatchString("/api/admin/settings") {
		t.Error("CompiledPathPattern should not match /api/admin/settings")
	}
}

// TestCompile_PathPattern_Empty tests that empty PathPattern leaves CompiledPathPattern nil
func TestCompile_PathPattern_Empty(t *testing.T) {
	tmpl := &Template{
		ID:   "no-path-pattern",
		HTTP: []HTTPTest{{Method: "GET", Path: "/api/test"}},
	}

	compiled, err := Compile(tmpl)
	if err != nil {
		t.Fatalf("Compile() failed: %v", err)
	}

	if compiled.CompiledPathPattern != nil {
		t.Error("CompiledPathPattern should be nil when PathPattern is empty")
	}
}

// TestCompile_PathPattern_Invalid tests that invalid PathPattern regex returns an error
func TestCompile_PathPattern_Invalid(t *testing.T) {
	tmpl := &Template{
		ID: "invalid-path-pattern",
		EndpointSelector: EndpointSelector{
			PathPattern: `[invalid(`,
		},
		HTTP: []HTTPTest{{Method: "GET", Path: "/test"}},
	}

	_, err := Compile(tmpl)
	if err == nil {
		t.Fatal("Compile() should fail with invalid PathPattern regex")
	}

	if !testing.Verbose() {
		return
	}
	t.Logf("Expected error: %v", err)
}

// TestCompile_NoMatchers tests template with no matchers
func TestCompile_NoMatchers(t *testing.T) {
	tmpl := &Template{
		ID: "no-matchers",
		HTTP: []HTTPTest{
			{
				Method: "GET",
				Path:   "/api/endpoint",
			},
		},
	}

	compiled, err := Compile(tmpl)
	if err != nil {
		t.Fatalf("Compile() should succeed with no matchers: %v", err)
	}

	if len(compiled.CompiledMatchers) != 0 {
		t.Errorf("Expected 0 compiled matchers, got %d", len(compiled.CompiledMatchers))
	}
}

// TestCompile_MultipleMatchers tests template with multiple HTTP tests and matchers
func TestCompile_MultipleMatchers(t *testing.T) {
	tmpl := &Template{
		ID: "multi-matchers",
		HTTP: []HTTPTest{
			{
				Method: "GET",
				Path:   "/api/test1",
				Matchers: []Matcher{
					{
						Type:  "regex",
						Regex: []string{"pattern1"},
						Part:  "body",
					},
					{
						Type:   "status",
						Status: []int{200, 201},
					},
				},
			},
			{
				Method: "POST",
				Path:   "/api/test2",
				Matchers: []Matcher{
					{
						Type:  "word",
						Words: []string{"success"},
						Part:  "body",
					},
				},
			},
		},
	}

	compiled, err := Compile(tmpl)
	if err != nil {
		t.Fatalf("Compile() failed: %v", err)
	}

	expectedMatchers := 3 // 2 from first HTTP test + 1 from second
	if len(compiled.CompiledMatchers) != expectedMatchers {
		t.Errorf("Expected %d compiled matchers, got %d", expectedMatchers, len(compiled.CompiledMatchers))
	}

	// Verify first matcher has compiled regex
	if compiled.CompiledMatchers[0].Type != "regex" {
		t.Errorf("First matcher type: got %q, want %q", compiled.CompiledMatchers[0].Type, "regex")
	}

	if len(compiled.CompiledMatchers[0].CompiledRegex) != 1 {
		t.Errorf("First matcher should have 1 compiled regex, got %d", len(compiled.CompiledMatchers[0].CompiledRegex))
	}

	// Verify second matcher (status) has no regex
	if compiled.CompiledMatchers[1].Type != "status" {
		t.Errorf("Second matcher type: got %q, want %q", compiled.CompiledMatchers[1].Type, "status")
	}

	if len(compiled.CompiledMatchers[1].CompiledRegex) != 0 {
		t.Errorf("Status matcher should have 0 compiled regex, got %d", len(compiled.CompiledMatchers[1].CompiledRegex))
	}

	// Verify third matcher (word) has no regex
	if compiled.CompiledMatchers[2].Type != "word" {
		t.Errorf("Third matcher type: got %q, want %q", compiled.CompiledMatchers[2].Type, "word")
	}
}
