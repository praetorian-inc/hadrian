package ssti

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// EngineFamily represents a template engine syntax family
type EngineFamily string

const (
	FamilyCurlyBraces      EngineFamily = "curly_braces"      // {{...}} - Jinja2, Twig, Pebble, Handlebars
	FamilyDollarSign       EngineFamily = "dollar_sign"       // ${...} - FreeMarker, Velocity, Mako, Thymeleaf
	FamilyErbStyle         EngineFamily = "erb_style"         // <%=...%> - ERB
	FamilyHashInterpolation EngineFamily = "hash_interpolation" // #{...} - Pug
	FamilyAtSign           EngineFamily = "at_sign"           // @(...) - Razor
	FamilySmarty           EngineFamily = "smarty"            // {math...} - Smarty
)

// FingerprintProbe represents a polymorphic probe for detecting engine families
type FingerprintProbe struct {
	Payload      string
	Expected     string
	TargetFamily EngineFamily
}

// ProbeResult tracks individual fingerprint probe results
type ProbeResult struct {
	Probe    FingerprintProbe
	Detected bool
	Evidence string
}

// FingerprintResult represents the result of engine fingerprinting
type FingerprintResult struct {
	DetectedFamilies map[EngineFamily]bool
	CandidateEngines []string
	ConfirmedEngines []string
	RequestCount     int
	ProbeResults     []ProbeResult
}

// IsVulnerable returns true if any candidate or confirmed engines exist
func (r *FingerprintResult) IsVulnerable() bool {
	return len(r.CandidateEngines) > 0 || len(r.ConfirmedEngines) > 0
}

// Fingerprinter performs engine fingerprinting for SSTI detection
type Fingerprinter struct {
	client *http.Client
	module *SSTIModule
}

// NewFingerprinter creates a new fingerprinter instance
func NewFingerprinter(client *http.Client) *Fingerprinter {
	return &Fingerprinter{
		client: client,
		module: NewSSTIModule(),
	}
}

// GetEngineFamilies returns the mapping of engine families to engine names
func GetEngineFamilies() map[EngineFamily][]string {
	return map[EngineFamily][]string{
		FamilyCurlyBraces:      {"jinja2", "twig", "pebble", "handlebars"},
		FamilyDollarSign:       {"freemarker", "velocity", "mako", "thymeleaf"},
		FamilyErbStyle:         {"erb"},
		FamilyHashInterpolation: {"pug"},
		FamilyAtSign:           {"razor"},
		FamilySmarty:           {"smarty"},
	}
}

// GetFingerprintProbes returns polymorphic probes for detecting engine families
// Uses uncommon arithmetic (7*191=1337) to avoid false positives
func GetFingerprintProbes() []FingerprintProbe {
	return []FingerprintProbe{
		{
			Payload:      "{{7*191}}",
			Expected:     "1337",
			TargetFamily: FamilyCurlyBraces,
		},
		{
			Payload:      "${7*191}",
			Expected:     "1337",
			TargetFamily: FamilyDollarSign,
		},
		{
			Payload:      "<%= 7*191 %>",
			Expected:     "1337",
			TargetFamily: FamilyErbStyle,
		},
		{
			Payload:      "#{7*191}",
			Expected:     "1337",
			TargetFamily: FamilyHashInterpolation,
		},
		{
			Payload:      "@(7*191)",
			Expected:     "1337",
			TargetFamily: FamilyAtSign,
		},
		{
			Payload:      "{math equation=\"7*191\"}",
			Expected:     "1337",
			TargetFamily: FamilySmarty,
		},
	}
}

// Fingerprint sends polymorphic probes and detects engine families
func (f *Fingerprinter) Fingerprint(targetURL, param, method string) (*FingerprintResult, error) {
	result := &FingerprintResult{
		DetectedFamilies: make(map[EngineFamily]bool),
		CandidateEngines: []string{},
		ConfirmedEngines: []string{},
		ProbeResults:     []ProbeResult{},
		RequestCount:     0,
	}

	probes := GetFingerprintProbes()
	families := GetEngineFamilies()

	// Send all fingerprint probes
	for _, probe := range probes {
		detected, evidence, err := f.sendProbe(targetURL, param, method, probe.Payload, probe.Expected)
		if err != nil {
			// Continue on error - don't fail entire fingerprint
			continue
		}

		result.RequestCount++

		probeResult := ProbeResult{
			Probe:    probe,
			Detected: detected,
			Evidence: evidence,
		}
		result.ProbeResults = append(result.ProbeResults, probeResult)

		if detected {
			result.DetectedFamilies[probe.TargetFamily] = true

			// Add candidate engines for this family
			if engines, ok := families[probe.TargetFamily]; ok {
				result.CandidateEngines = append(result.CandidateEngines, engines...)
			}
		}
	}

	return result, nil
}

// sendProbe sends a single probe and checks for expected response
func (f *Fingerprinter) sendProbe(targetURL, param, method, payload, expected string) (bool, string, error) {
	var req *http.Request
	var err error

	if method == "GET" {
		u, parseErr := url.Parse(targetURL)
		if parseErr != nil {
			return false, "", parseErr
		}

		q := u.Query()
		q.Set(param, payload)
		u.RawQuery = q.Encode()

		req, err = http.NewRequest("GET", u.String(), nil)
	} else {
		// POST
		data := fmt.Sprintf("%s=%s", param, url.QueryEscape(payload))
		req, err = http.NewRequest("POST", targetURL, strings.NewReader(data))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	if err != nil {
		return false, "", err
	}

	// Send request
	resp, err := f.client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}

	bodyStr := string(body)

	// Check if expected value is in response
	detected := strings.Contains(bodyStr, expected)

	return detected, bodyStr, nil
}

// ConfirmEngine runs verification chain for a specific engine
func (f *Fingerprinter) ConfirmEngine(targetURL, param, method, engine string) (bool, error) {
	// Build verification chain for the specific engine
	chain, err := f.buildVerificationChain(engine)
	if err != nil {
		return false, err
	}

	if len(chain) == 0 {
		// No specific chain, use generic arithmetic verification
		chain = []PayloadWithExpected{
			{Value: "{{13*37}}", Expected: "481", Description: "Generic arithmetic 1"},
			{Value: "{{17*89}}", Expected: "1513", Description: "Generic arithmetic 2"},
			{Value: "{{7*191}}", Expected: "1337", Description: "Generic arithmetic 3"},
		}

		// Adjust payload syntax based on engine
		chain = f.adjustChainForEngine(chain, engine)
	}

	// Run verification chain
	result := f.module.VerifyEngine(f.client, targetURL, param, method, engine, chain)

	// Confirmed if all passes succeed OR at least one pass (in fingerprinting context)
	// When used after fingerprinting, even partial confirmation is useful
	return result.Confirmed || result.PassCount > 0, nil
}

// buildVerificationChain builds a verification chain for a specific engine
func (f *Fingerprinter) buildVerificationChain(engine string) ([]PayloadWithExpected, error) {
	// Engine-specific verification chains
	switch engine {
	case "jinja2":
		return []PayloadWithExpected{
			{Value: "{{7*191}}", Expected: "1337", Description: "Basic arithmetic"},
			{Value: "{{'test'|upper}}", Expected: "TEST", Description: "Jinja2-specific filter"},
			{Value: "{{range(5)|list}}", Expected: "[0, 1, 2, 3, 4]", Description: "Jinja2-specific range function"},
		}, nil

	case "twig":
		return []PayloadWithExpected{
			{Value: "{{7*191}}", Expected: "1337", Description: "Basic arithmetic"},
			{Value: "{{'test'|upper}}", Expected: "TEST", Description: "Twig filter (same as Jinja2)"},
			{Value: "{{random(1000)}}", Expected: "", Description: "Twig-specific random (check response contains number)"},
		}, nil

	case "pebble":
		return []PayloadWithExpected{
			{Value: "{{ 7 * 191 }}", Expected: "1337", Description: "Basic arithmetic with spaces"},
			{Value: "{{ 'test' | upper }}", Expected: "TEST", Description: "Pebble filter with spaces"},
			{Value: "{{ beans }}", Expected: "", Description: "Pebble-specific beans variable (may error)"},
		}, nil

	case "handlebars":
		return []PayloadWithExpected{
			{Value: "{{7*191}}", Expected: "7*191", Description: "Handlebars doesn't evaluate - returns literal"},
			{Value: "{{#if true}}YES{{/if}}", Expected: "YES", Description: "Handlebars conditional helper"},
			{Value: "{{#each items}}x{{/each}}", Expected: "", Description: "Handlebars each helper"},
		}, nil

	case "freemarker":
		return []PayloadWithExpected{
			{Value: "${7*191}", Expected: "1337", Description: "Basic arithmetic"},
			{Value: "${13*37}", Expected: "481", Description: "Alternative arithmetic"},
			{Value: "${17*89}", Expected: "1513", Description: "Third arithmetic"},
		}, nil

	case "velocity":
		return []PayloadWithExpected{
			{Value: "${7*191}", Expected: "1337", Description: "Basic arithmetic"},
			{Value: "${13*37}", Expected: "481", Description: "Alternative arithmetic"},
			{Value: "${17*89}", Expected: "1513", Description: "Third arithmetic"},
		}, nil

	case "mako":
		return []PayloadWithExpected{
			{Value: "${7*191}", Expected: "1337", Description: "Basic arithmetic"},
			{Value: "${13*37}", Expected: "481", Description: "Alternative arithmetic"},
			{Value: "${17*89}", Expected: "1513", Description: "Third arithmetic"},
		}, nil

	case "thymeleaf":
		return []PayloadWithExpected{
			{Value: "${7*191}", Expected: "1337", Description: "Basic arithmetic"},
			{Value: "${13*37}", Expected: "481", Description: "Alternative arithmetic"},
			{Value: "${17*89}", Expected: "1513", Description: "Third arithmetic"},
		}, nil

	case "erb":
		return []PayloadWithExpected{
			{Value: "<%= 7*191 %>", Expected: "1337", Description: "Basic arithmetic"},
			{Value: "<%= 13*37 %>", Expected: "481", Description: "Alternative arithmetic"},
			{Value: "<%= 17*89 %>", Expected: "1513", Description: "Third arithmetic"},
		}, nil

	case "pug":
		return []PayloadWithExpected{
			{Value: "#{7*191}", Expected: "1337", Description: "Basic arithmetic"},
			{Value: "#{13*37}", Expected: "481", Description: "Alternative arithmetic"},
			{Value: "#{17*89}", Expected: "1513", Description: "Third arithmetic"},
		}, nil

	case "razor":
		return []PayloadWithExpected{
			{Value: "@(7*191)", Expected: "1337", Description: "Basic arithmetic"},
			{Value: "@(13*37)", Expected: "481", Description: "Alternative arithmetic"},
			{Value: "@(17*89)", Expected: "1513", Description: "Third arithmetic"},
		}, nil

	case "smarty":
		return []PayloadWithExpected{
			{Value: "{math equation=\"7*191\"}", Expected: "1337", Description: "Math function"},
			{Value: "{math equation=\"13*37\"}", Expected: "481", Description: "Alternative arithmetic"},
			{Value: "{math equation=\"17*89\"}", Expected: "1513", Description: "Third arithmetic"},
		}, nil

	default:
		// Return empty chain for unknown engines
		return []PayloadWithExpected{}, nil
	}
}

// adjustChainForEngine adjusts payload syntax for specific engine families
func (f *Fingerprinter) adjustChainForEngine(chain []PayloadWithExpected, engine string) []PayloadWithExpected {
	adjusted := make([]PayloadWithExpected, len(chain))

	for i, payload := range chain {
		adjusted[i] = payload

		// Adjust syntax based on engine
		switch engine {
		case "freemarker", "velocity", "mako", "thymeleaf":
			// Convert {{...}} to ${...}
			adjusted[i].Value = strings.ReplaceAll(payload.Value, "{{", "${")
			adjusted[i].Value = strings.ReplaceAll(adjusted[i].Value, "}}", "}")

		case "erb":
			// Convert {{...}} to <%= ... %>
			adjusted[i].Value = strings.ReplaceAll(payload.Value, "{{", "<%= ")
			adjusted[i].Value = strings.ReplaceAll(adjusted[i].Value, "}}", " %>")

		case "pug":
			// Convert {{...}} to #{...}
			adjusted[i].Value = strings.ReplaceAll(payload.Value, "{{", "#{")
			adjusted[i].Value = strings.ReplaceAll(adjusted[i].Value, "}}", "}")

		case "razor":
			// Convert {{...}} to @(...)
			adjusted[i].Value = strings.ReplaceAll(payload.Value, "{{", "@(")
			adjusted[i].Value = strings.ReplaceAll(adjusted[i].Value, "}}", ")")

		case "smarty":
			// Convert {{...}} to {math equation="..."}
			inner := strings.TrimPrefix(payload.Value, "{{")
			inner = strings.TrimSuffix(inner, "}}")
			adjusted[i].Value = fmt.Sprintf("{math equation=\"%s\"}", inner)
		}
	}

	return adjusted
}

// FingerprintAndConfirm runs the complete two-phase workflow
func (f *Fingerprinter) FingerprintAndConfirm(targetURL, param, method string) (*FingerprintResult, error) {
	// Phase 1: Fingerprint to detect families
	result, err := f.Fingerprint(targetURL, param, method)
	if err != nil {
		return nil, err
	}

	// If no families detected, return immediately
	if len(result.DetectedFamilies) == 0 {
		return result, nil
	}

	// Phase 2: Confirm only engines from detected families
	families := GetEngineFamilies()

	for family, detected := range result.DetectedFamilies {
		if !detected {
			continue
		}

		// Get engines for this family
		engines, ok := families[family]
		if !ok {
			continue
		}

		// Confirm each engine in the family
		for _, engine := range engines {
			confirmed, err := f.ConfirmEngine(targetURL, param, method, engine)
			if err != nil {
				// Continue on error
				continue
			}

			// Count the confirmation requests (3 per engine)
			result.RequestCount += 3

			if confirmed {
				result.ConfirmedEngines = append(result.ConfirmedEngines, engine)
			}
		}
	}

	return result, nil
}
