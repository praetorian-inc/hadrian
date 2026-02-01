package owasp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/owasp"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// Example_requestIDTracking demonstrates how request IDs are tracked across all phases
func Example_requestIDTracking() {
	// Setup a mock API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server receives and can log the X-Hadrian-Request-Id header
		_ = r.Header.Get("X-Hadrian-Request-Id") // Available for logging

		switch r.URL.Path {
		case "/api/videos":
			// Setup phase: Create resource
			fmt.Println("Setup request received with X-Hadrian-Request-Id")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"id": "video123"})

		case "/api/videos/video123":
			// Attack/Verify phases
			if r.Header.Get("Authorization") == "Bearer attacker-token" {
				fmt.Println("Attack request received with X-Hadrian-Request-Id")
			} else {
				fmt.Println("Verify request received with X-Hadrian-Request-Id")
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"id": "video123", "title": "Video"})
		}
	}))
	defer server.Close()

	// Create a mutation test template
	tmpl := &templates.Template{
		ID: "bola-test",
		Info: templates.TemplateInfo{
			Name:     "BOLA Test",
			Category: "API1",
			Severity: "HIGH",
		},
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Operation:          "create",
					Path:               "/api/videos",
					Auth:               "victim",
					StoreResponseField: "id",
				},
			},
			Attack: &templates.Phase{
				Operation:      "read",
				Path:           "/api/videos/{id}",
				Auth:           "attacker",
				UseStoredField: "id",
				ExpectedStatus: http.StatusOK,
			},
			Verify: &templates.Phase{
				Operation:      "read",
				Path:           "/api/videos/{id}",
				Auth:           "victim",
				UseStoredField: "id",
				ExpectedStatus: http.StatusOK,
			},
		},
	}

	// Execute the test
	executor := owasp.NewMutationExecutor(http.DefaultClient)
	authInfos := map[string]*auth.AuthInfo{
		"attacker": {Method: "bearer", Value: "Bearer attacker-token"},
		"victim":   {Method: "bearer", Value: "Bearer victim-token"},
	}
	result, _ := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"create",
		"attacker",
		"victim",
		authInfos,
		server.URL,
	)

	// Show the tracked request IDs
	fmt.Printf("\nVulnerability detected: %v\n", result.Matched)
	fmt.Printf("Total request IDs tracked: %d\n",
		len(result.RequestIDs.Setup) +
		len(result.RequestIDs.Attack) +
		len(result.RequestIDs.Verify))

	fmt.Printf("Setup phase IDs: %d\n", len(result.RequestIDs.Setup))
	fmt.Printf("Attack phase IDs: %d\n", len(result.RequestIDs.Attack))
	fmt.Printf("Verify phase IDs: %d\n", len(result.RequestIDs.Verify))

	// Output:
	// Setup request received with X-Hadrian-Request-Id
	// Attack request received with X-Hadrian-Request-Id
	// Verify request received with X-Hadrian-Request-Id
	//
	// Vulnerability detected: true
	// Total request IDs tracked: 3
	// Setup phase IDs: 1
	// Attack phase IDs: 1
	// Verify phase IDs: 1
}
