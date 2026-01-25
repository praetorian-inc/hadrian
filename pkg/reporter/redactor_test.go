package reporter

import (
	"strings"
	"testing"
)

// Test SSN redaction
func TestRedactSSN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "SSN in JSON",
			input:    `{"ssn": "123-45-6789"}`,
			expected: `{"ssn": "[SSN-REDACTED]"}`,
		},
		{
			name:     "SSN in text",
			input:    `SSN: 987-65-4321`,
			expected: `SSN: [SSN-REDACTED]`,
		},
		{
			name:     "No SSN",
			input:    `No SSN here`,
			expected: `No SSN here`,
		},
		{
			name:     "Multiple SSNs",
			input:    `First: 123-45-6789, Second: 987-65-4321`,
			expected: `First: [SSN-REDACTED], Second: [SSN-REDACTED]`,
		},
	}

	redactor := NewRedactor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test credit card redaction
func TestRedactCreditCard(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Credit card with dashes",
			input:    `Card: 4532-1234-5678-9010`,
			expected: `Card: [CREDIT_CARD-REDACTED]`,
		},
		{
			name:     "Credit card with spaces",
			input:    `Card: 4532 1234 5678 9010`,
			expected: `Card: [CREDIT_CARD-REDACTED]`,
		},
		{
			name:     "Credit card no separators",
			input:    `Card: 4532123456789010`,
			expected: `Card: [CREDIT_CARD-REDACTED]`,
		},
	}

	redactor := NewRedactor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test email redaction
func TestRedactEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple email",
			input:    `Email: user@example.com`,
			expected: `Email: [EMAIL-REDACTED]`,
		},
		{
			name:     "Email with dots",
			input:    `Contact: john.doe@company.co.uk`,
			expected: `Contact: [EMAIL-REDACTED]`,
		},
		{
			name:     "Multiple emails",
			input:    `user1@test.com and user2@test.com`,
			expected: `[EMAIL-REDACTED] and [EMAIL-REDACTED]`,
		},
	}

	redactor := NewRedactor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test phone number redaction
func TestRedactPhone(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Phone with dashes",
			input:    `Call: 555-123-4567`,
			expected: `Call: [PHONE-REDACTED]`,
		},
		{
			name:     "Phone with parentheses",
			input:    `Phone: (555) 123-4567`,
			expected: `Phone: [PHONE-REDACTED]`,
		},
		{
			name:     "Phone with dots",
			input:    `Contact: 555.123.4567`,
			expected: `Contact: [PHONE-REDACTED]`,
		},
	}

	redactor := NewRedactor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test JWT redaction
func TestRedactJWT(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Valid JWT",
			input:    `Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
			expected: `Token: [JWT-REDACTED]`,
		},
		{
			name:     "JWT in JSON",
			input:    `{"jwt":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123"}`,
			expected: `{"jwt":"[JWT-REDACTED]"}`,
		},
	}

	redactor := NewRedactor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test Bearer token redaction
func TestRedactBearer(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Bearer token",
			input:    `Authorization: Bearer abc123def456`,
			expected: `Authorization: [BEARER-REDACTED]`,
		},
		{
			name:     "Bearer lowercase",
			input:    `Auth: bearer xyz789`,
			expected: `Auth: [BEARER-REDACTED]`,
		},
	}

	redactor := NewRedactor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test Basic auth redaction
func TestRedactBasic(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Basic auth",
			input:    `Authorization: Basic dXNlcjpwYXNzd29yZA==`,
			expected: `Authorization: [BASIC-REDACTED]`,
		},
		{
			name:     "Basic lowercase",
			input:    `Auth: basic QWxhZGRpbjpPcGVuU2VzYW1l`,
			expected: `Auth: [BASIC-REDACTED]`,
		},
	}

	redactor := NewRedactor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test API key redaction
func TestRedactAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "API key with underscore",
			input:    `api_key: sk_live_abc123`,
			expected: `[API_KEY-REDACTED]`,
		},
		{
			name:     "API key with dash",
			input:    `api-key: "prod-key-xyz789"`,
			expected: `[API_KEY-REDACTED]`,
		},
		{
			name:     "Token field with api prefix",
			input:    `api-token="secret123"`,
			expected: `[API_KEY-REDACTED]`,
		},
		{
			name:     "apikey no separator",
			input:    `apikey: value123`,
			expected: `[API_KEY-REDACTED]`,
		},
	}

	redactor := NewRedactor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test password redaction
func TestRedactPassword(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Password field",
			input:    `password: "MySecret123"`,
			expected: `[PASSWORD-REDACTED]`,
		},
		{
			name:     "Passwd field",
			input:    `passwd="admin123"`,
			expected: `[PASSWORD-REDACTED]`,
		},
		{
			name:     "Pwd field",
			input:    `pwd: secret`,
			expected: `[PASSWORD-REDACTED]`,
		},
	}

	redactor := NewRedactor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test Stripe/Twilio style API keys
func TestRedactSKKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Stripe secret key",
			input:    `Key: sk_live_abcdefghijklmnopqrstuvwxyz`,
			expected: `Key: [SK_KEY-REDACTED]`,
		},
		{
			name:     "Stripe publishable key",
			input:    `Key: pk_test_1234567890abcdefghij`,
			expected: `Key: [SK_KEY-REDACTED]`,
		},
	}

	redactor := NewRedactor()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test RedactWithHash preserves comparison ability
func TestRedactWithHash(t *testing.T) {
	redactor := NewRedactor()

	input1 := `SSN: 123-45-6789`
	input2 := `SSN: 123-45-6789`
	input3 := `SSN: 987-65-4321`

	result1 := redactor.RedactWithHash(input1)
	result2 := redactor.RedactWithHash(input2)
	result3 := redactor.RedactWithHash(input3)

	// Same SSN should produce same hash
	if result1 != result2 {
		t.Errorf("Same input should produce same hash: %q != %q", result1, result2)
	}

	// Different SSN should produce different hash
	if result1 == result3 {
		t.Errorf("Different input should produce different hash")
	}

	// Should contain SSN-REDACTED marker
	if !strings.Contains(result1, "[SSN-REDACTED:sha256=") {
		t.Errorf("Hash result should contain marker: %q", result1)
	}
}

// Test TruncateForLLM with small response
func TestTruncateForLLM_NoTruncation(t *testing.T) {
	input := strings.Repeat("a", 100)
	result := TruncateForLLM(input)

	if result != input {
		t.Errorf("Small response should not be truncated")
	}
}

// Test TruncateForLLM with large response
func TestTruncateForLLM_Truncation(t *testing.T) {
	input := strings.Repeat("a", 10000)
	result := TruncateForLLM(input)

	if len(result) != 8192+len("\n[TRUNCATED - Original size: 10000 bytes]") {
		t.Errorf("Large response should be truncated to 8192 bytes")
	}

	if !strings.Contains(result, "[TRUNCATED") {
		t.Errorf("Truncated response should contain marker")
	}

	if !strings.Contains(result, "10000") {
		t.Errorf("Truncated response should show original size")
	}
}

// Test RedactForLLM combines both redaction and truncation
func TestRedactForLLM(t *testing.T) {
	redactor := NewRedactor()

	tests := []struct {
		name     string
		input    string
		wantLen  int
		contains []string
	}{
		{
			name:     "Small response with PII",
			input:    `{"ssn":"123-45-6789","email":"user@example.com"}`,
			wantLen:  len(`{"ssn":"[SSN-REDACTED]","email":"[EMAIL-REDACTED]"}`),
			contains: []string{"[SSN-REDACTED]", "[EMAIL-REDACTED]"},
		},
		{
			name:     "Large response with PII",
			input:    strings.Repeat(`{"ssn":"123-45-6789"}`, 1000),
			wantLen:  8192 + len("\n[TRUNCATED - Original size: ") + 5 + len(" bytes]"), // Approximate
			contains: []string{"[SSN-REDACTED]", "[TRUNCATED"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.RedactForLLM(tt.input)

			for _, want := range tt.contains {
				if !strings.Contains(result, want) {
					t.Errorf("RedactForLLM() should contain %q", want)
				}
			}
		})
	}
}

// Test combined redaction of multiple PII types
func TestRedactMultiplePII(t *testing.T) {
	redactor := NewRedactor()

	input := `{
		"ssn": "123-45-6789",
		"email": "user@example.com",
		"phone": "555-123-4567",
		"card": "4532-1234-5678-9010",
		"token": "Bearer abc123def456",
		"apiKey": "sk_live_secretkey123"
	}`

	result := redactor.Redact(input)

	// All PII should be redacted
	if strings.Contains(result, "123-45-6789") {
		t.Errorf("SSN should be redacted")
	}
	if strings.Contains(result, "user@example.com") {
		t.Errorf("Email should be redacted")
	}
	if strings.Contains(result, "555-123-4567") {
		t.Errorf("Phone should be redacted")
	}
	if strings.Contains(result, "4532-1234-5678-9010") {
		t.Errorf("Credit card should be redacted")
	}
	if strings.Contains(result, "abc123def456") {
		t.Errorf("Bearer token should be redacted")
	}
	if strings.Contains(result, "sk_live_secretkey123") {
		t.Errorf("API key should be redacted")
	}

	// All PII values should be redacted (check original values don't appear)
	secretValues := []string{
		"123-45-6789",
		"user@example.com",
		"555-123-4567",
		"4532-1234-5678-9010",
		"abc123def456",
		"sk_live_secretkey123",
	}

	for _, secret := range secretValues {
		if strings.Contains(result, secret) {
			t.Errorf("Secret value should be redacted: %q", secret)
		}
	}

	// Some redaction markers should be present
	// Note: sk_key gets replaced by api_key pattern, so we check for REDACTED markers
	requiredMarkers := []string{
		"[SSN-REDACTED]",
		"[EMAIL-REDACTED]",
		"[PHONE-REDACTED]",
		"[CREDIT_CARD-REDACTED]",
		"[BEARER-REDACTED]",
		// api_key will match "apiKey": "[SK_KEY-REDACTED]" and replace the whole thing
		"[API_KEY-REDACTED]",
	}

	for _, marker := range requiredMarkers {
		if !strings.Contains(result, marker) {
			t.Errorf("Should contain redaction marker: %q", marker)
		}
	}
}
