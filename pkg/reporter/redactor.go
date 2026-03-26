package reporter

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

// Redactor sanitizes sensitive data from output (PII protection)
type Redactor struct {
	patterns map[string]*regexp.Regexp
}

// NewRedactor creates a new Redactor with pre-compiled patterns
func NewRedactor() *Redactor {
	return &Redactor{
		patterns: map[string]*regexp.Regexp{
			// PII patterns (PII protection)
			"ssn":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			"credit_card": regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),
			"email":       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			"phone":       regexp.MustCompile(`\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),

			// Credential patterns (PII protection)
			// Order matters: JWT first (most specific), then sk_key, then bearer/basic, then api_key/password
			"jwt":      regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`),
			"sk_key":   regexp.MustCompile(`[sp]k[-_][A-Za-z0-9_]{10,}`),
			"bearer":   regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_.]+`),
			"basic":    regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/=]+`),
			"api_key":  regexp.MustCompile(`(?i)(api[_-]?(key|token)|apikey)["']?\s*[:=]\s*["']?[^"'\s]+["']?`),
			"password": regexp.MustCompile(`(?i)(password|passwd|pwd)["']?\s*[:=]\s*["']?[^"'\s]+["']?`),

			// Session cookie patterns (PII protection)
			"cookie": regexp.MustCompile(`(?i)(cookie|set-cookie)\s*:\s*[^\r\n]+`),
		},
	}
}

// Redact replaces sensitive data with [REDACTED] markers (PII protection)
// Patterns are applied in two passes:
// Pass 1: Standalone values (JWT, sk_key, bearer, basic) - these don't need field names
// Pass 2: Field:value pairs (api_key, password) - these match "key: value" patterns
// Pass 3: PII patterns (ssn, credit_card, email, phone)
func (r *Redactor) Redact(content string) string {
	// Pass 1: Standalone credential values (most specific)
	pass1Order := []string{"jwt", "sk_key", "bearer", "basic"}
	for _, name := range pass1Order {
		if pattern, ok := r.patterns[name]; ok {
			content = pattern.ReplaceAllStringFunc(content, func(match string) string {
				return fmt.Sprintf("[%s-REDACTED]", strings.ToUpper(name))
			})
		}
	}

	// Pass 2: Field:value pairs
	pass2Order := []string{"api_key", "password", "cookie"}
	for _, name := range pass2Order {
		if pattern, ok := r.patterns[name]; ok {
			content = pattern.ReplaceAllStringFunc(content, func(match string) string {
				return fmt.Sprintf("[%s-REDACTED]", strings.ToUpper(name))
			})
		}
	}

	// Pass 3: PII patterns
	pass3Order := []string{"ssn", "credit_card", "email", "phone"}
	for _, name := range pass3Order {
		if pattern, ok := r.patterns[name]; ok {
			content = pattern.ReplaceAllStringFunc(content, func(match string) string {
				return fmt.Sprintf("[%s-REDACTED]", strings.ToUpper(name))
			})
		}
	}

	return content
}

// RedactWithHash replaces with hash for comparison (PII protection)
func (r *Redactor) RedactWithHash(content string) string {
	// Pass 1: Standalone credential values
	pass1Order := []string{"jwt", "sk_key", "bearer", "basic"}
	for _, name := range pass1Order {
		if pattern, ok := r.patterns[name]; ok {
			content = pattern.ReplaceAllStringFunc(content, func(match string) string {
				hash := sha256.Sum256([]byte(match))
				return fmt.Sprintf("[%s-REDACTED:sha256=%x]", strings.ToUpper(name), hash[:8])
			})
		}
	}

	// Pass 2: Field:value pairs
	pass2Order := []string{"api_key", "password", "cookie"}
	for _, name := range pass2Order {
		if pattern, ok := r.patterns[name]; ok {
			content = pattern.ReplaceAllStringFunc(content, func(match string) string {
				hash := sha256.Sum256([]byte(match))
				return fmt.Sprintf("[%s-REDACTED:sha256=%x]", strings.ToUpper(name), hash[:8])
			})
		}
	}

	// Pass 3: PII patterns
	pass3Order := []string{"ssn", "credit_card", "email", "phone"}
	for _, name := range pass3Order {
		if pattern, ok := r.patterns[name]; ok {
			content = pattern.ReplaceAllStringFunc(content, func(match string) string {
				hash := sha256.Sum256([]byte(match))
				return fmt.Sprintf("[%s-REDACTED:sha256=%x]", strings.ToUpper(name), hash[:8])
			})
		}
	}

	return content
}

// TruncateForLLM limits response size before LLM (data minimization)
func TruncateForLLM(response string) string {
	const MaxLLMResponseSize = 8192 // 8KB

	if len(response) > MaxLLMResponseSize {
		return response[:MaxLLMResponseSize] + "\n[TRUNCATED - Original size: " + fmt.Sprintf("%d", len(response)) + " bytes]"
	}

	return response
}

// RedactForLLM combines redaction + truncation (mandatory before LLM)
func (r *Redactor) RedactForLLM(response string) string {
	redacted := r.Redact(response)
	truncated := TruncateForLLM(redacted)
	return truncated
}
