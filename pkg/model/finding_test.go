package model

import (
	"testing"
	"time"
)

func TestFinding(t *testing.T) {
	t.Run("initialize with all fields", func(t *testing.T) {
		now := time.Now()
		finding := &Finding{
			ID:              "finding-123",
			Category:        "API1",
			Name:            "Broken Object Level Authorization",
			Description:     "User can access other user's data",
			Severity:        SeverityCritical,
			Confidence:      0.95,
			IsVulnerability: true,
			Endpoint:        "GET /api/users/{id}",
			Method:          "GET",
			AttackerRole:    "user",
			VictimRole:      "admin",
			Evidence: Evidence{
				Request:  HTTPRequest{Method: "GET", URL: "/api/users/123"},
				Response: HTTPResponse{StatusCode: 200, Body: "data"},
			},
			LLMAnalysis: &LLMTriage{
				Provider:        "claude",
				IsVulnerability: true,
				Confidence:      0.9,
			},
			Timestamp: now,
		}

		if finding.ID != "finding-123" {
			t.Errorf("expected ID=finding-123, got %s", finding.ID)
		}
		if finding.Category != "API1" {
			t.Errorf("expected Category=API1, got %s", finding.Category)
		}
		if finding.Severity != SeverityCritical {
			t.Errorf("expected Severity=CRITICAL, got %s", finding.Severity)
		}
		if finding.Confidence != 0.95 {
			t.Errorf("expected Confidence=0.95, got %f", finding.Confidence)
		}
		if !finding.IsVulnerability {
			t.Error("expected IsVulnerability=true")
		}
		if finding.Timestamp != now {
			t.Errorf("expected Timestamp=%v, got %v", now, finding.Timestamp)
		}
	})

	t.Run("without optional fields", func(t *testing.T) {
		finding := &Finding{
			ID:       "finding-456",
			Category: "API2",
			Severity: SeverityLow,
		}

		if finding.VictimRole != "" {
			t.Errorf("expected empty VictimRole, got %s", finding.VictimRole)
		}
		if finding.LLMAnalysis != nil {
			t.Error("expected LLMAnalysis to be nil")
		}
	})
}

func TestSeverity(t *testing.T) {
	t.Run("all severity constants", func(t *testing.T) {
		if SeverityCritical != "CRITICAL" {
			t.Errorf("expected CRITICAL, got %s", SeverityCritical)
		}
		if SeverityHigh != "HIGH" {
			t.Errorf("expected HIGH, got %s", SeverityHigh)
		}
		if SeverityMedium != "MEDIUM" {
			t.Errorf("expected MEDIUM, got %s", SeverityMedium)
		}
		if SeverityLow != "LOW" {
			t.Errorf("expected LOW, got %s", SeverityLow)
		}
		if SeverityInfo != "INFO" {
			t.Errorf("expected INFO, got %s", SeverityInfo)
		}
	})
}

func TestEvidence(t *testing.T) {
	t.Run("single phase evidence", func(t *testing.T) {
		evidence := Evidence{
			Request: HTTPRequest{
				Method: "GET",
				URL:    "/api/users/123",
				Headers: map[string]string{
					"Authorization": "Bearer token",
				},
			},
			Response: HTTPResponse{
				StatusCode: 200,
				Body:       "user data",
				BodyHash:   "abc123",
			},
		}

		if evidence.Request.Method != "GET" {
			t.Errorf("expected Method=GET, got %s", evidence.Request.Method)
		}
		if evidence.Response.StatusCode != 200 {
			t.Errorf("expected StatusCode=200, got %d", evidence.Response.StatusCode)
		}
	})

	t.Run("three phase mutation test evidence", func(t *testing.T) {
		evidence := Evidence{
			Request:  HTTPRequest{Method: "POST", URL: "/api/users"},
			Response: HTTPResponse{StatusCode: 201},
			SetupResponse: &HTTPResponse{
				StatusCode: 201,
				Body:       `{"id":"123"}`,
			},
			AttackResponse: &HTTPResponse{
				StatusCode: 200,
				Body:       `{"id":"123","data":"sensitive"}`,
			},
			VerifyResponse: &HTTPResponse{
				StatusCode: 200,
				Body:       `{"id":"123","data":"sensitive"}`,
			},
			ResourceID: "123",
		}

		if evidence.SetupResponse == nil {
			t.Error("expected SetupResponse to be set")
		}
		if evidence.AttackResponse == nil {
			t.Error("expected AttackResponse to be set")
		}
		if evidence.VerifyResponse == nil {
			t.Error("expected VerifyResponse to be set")
		}
		if evidence.ResourceID != "123" {
			t.Errorf("expected ResourceID=123, got %s", evidence.ResourceID)
		}
	})

	t.Run("OOB interaction evidence", func(t *testing.T) {
		now := time.Now()
		evidence := Evidence{
			Request:  HTTPRequest{Method: "POST", URL: "/graphql"},
			Response: HTTPResponse{StatusCode: 200},
			OOBInteractions: []OOBInteraction{
				{
					Protocol:  "http",
					URL:       "abc123.oast.live",
					Timestamp: now,
					RemoteIP:  "1.2.3.4",
					RawData:   "GET / HTTP/1.1\r\nHost: abc123.oast.live\r\n",
				},
			},
		}

		if len(evidence.OOBInteractions) != 1 {
			t.Errorf("expected 1 OOB interaction, got %d", len(evidence.OOBInteractions))
		}
		if evidence.OOBInteractions[0].Protocol != "http" {
			t.Errorf("expected Protocol=http, got %s", evidence.OOBInteractions[0].Protocol)
		}
		if evidence.OOBInteractions[0].RemoteIP != "1.2.3.4" {
			t.Errorf("expected RemoteIP=1.2.3.4, got %s", evidence.OOBInteractions[0].RemoteIP)
		}
	})
}

func TestHTTPRequest(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		req := HTTPRequest{
			Method: "POST",
			URL:    "/api/users",
			Headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer token",
			},
			Body: `{"name":"test"}`,
		}

		if req.Method != "POST" {
			t.Errorf("expected Method=POST, got %s", req.Method)
		}
		if req.URL != "/api/users" {
			t.Errorf("expected URL=/api/users, got %s", req.URL)
		}
		if len(req.Headers) != 2 {
			t.Errorf("expected 2 headers, got %d", len(req.Headers))
		}
		if req.Body != `{"name":"test"}` {
			t.Errorf("expected Body to match, got %s", req.Body)
		}
	})

	t.Run("without body", func(t *testing.T) {
		req := HTTPRequest{
			Method: "GET",
			URL:    "/api/users",
		}

		if req.Body != "" {
			t.Errorf("expected empty Body, got %s", req.Body)
		}
	})
}

func TestHTTPResponse(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		resp := HTTPResponse{
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body:      `{"data":"value"}`,
			BodyHash:  "sha256hash",
			Size:      16,
			Truncated: false,
		}

		if resp.StatusCode != 200 {
			t.Errorf("expected StatusCode=200, got %d", resp.StatusCode)
		}
		if resp.BodyHash != "sha256hash" {
			t.Errorf("expected BodyHash=sha256hash, got %s", resp.BodyHash)
		}
		if resp.Size != 16 {
			t.Errorf("expected Size=16, got %d", resp.Size)
		}
		if resp.Truncated {
			t.Error("expected Truncated=false")
		}
	})

	t.Run("truncated response", func(t *testing.T) {
		resp := HTTPResponse{
			StatusCode: 200,
			Body:       "truncated...",
			Truncated:  true,
		}

		if !resp.Truncated {
			t.Error("expected Truncated=true")
		}
	})
}

func TestLLMTriage(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		triage := &LLMTriage{
			Provider:        "claude",
			IsVulnerability: true,
			Confidence:      0.85,
			Reasoning:       "User can access unauthorized data",
			Recommendations: "Implement proper authorization checks",
		}

		if triage.Provider != "claude" {
			t.Errorf("expected Provider=claude, got %s", triage.Provider)
		}
		if !triage.IsVulnerability {
			t.Error("expected IsVulnerability=true")
		}
		if triage.Confidence != 0.85 {
			t.Errorf("expected Confidence=0.85, got %f", triage.Confidence)
		}
		if triage.Reasoning == "" {
			t.Error("expected Reasoning to be set")
		}
		if triage.Recommendations == "" {
			t.Error("expected Recommendations to be set")
		}
	})

	t.Run("different providers", func(t *testing.T) {
		providers := []string{"claude", "openai", "ollama"}

		for _, provider := range providers {
			triage := &LLMTriage{
				Provider:        provider,
				IsVulnerability: false,
				Confidence:      0.5,
			}

			if triage.Provider != provider {
				t.Errorf("expected Provider=%s, got %s", provider, triage.Provider)
			}
		}
	})
}
