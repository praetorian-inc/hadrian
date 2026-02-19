package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestResetEndpoint tests the POST /api/reset endpoint
func TestResetEndpoint(t *testing.T) {
	// Initialize data with custom values
	users = []User{
		{ID: 999, Username: "modified", Email: "modified@example.com", Role: "user", Password: "modified", APIKey: "modified-key"},
	}
	profiles = []Profile{
		{ID: 999, UserID: 999, FullName: "Modified User", SSN: "999-99-9999", PhoneNumber: "999-9999", Address: "999 Modified St"},
	}
	orders = []Order{}
	documents = []Document{}

	// Verify data is modified
	if len(users) != 1 || users[0].Username != "modified" {
		t.Fatal("Setup failed: data not modified")
	}

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/reset", nil)
	w := httptest.NewRecorder()

	// Create handler (no auth required)
	handler := http.HandlerFunc(handleReset)
	handler.ServeHTTP(w, req)

	// Check response status
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse response
	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Check response message
	if response["message"] != "Data store reset to initial state" {
		t.Errorf("Expected reset message, got: %s", response["message"])
	}

	// Check response contains counts
	expectedCounts := map[string]string{
		"users":     "3",
		"profiles":  "3",
		"orders":    "4",
		"documents": "4",
	}
	for key, expected := range expectedCounts {
		if response[key] != expected {
			t.Errorf("Expected %s=%s, got %s", key, expected, response[key])
		}
	}

	// Verify data was actually reset
	if len(users) != 3 {
		t.Errorf("Expected 3 users after reset, got %d", len(users))
	}
	if len(profiles) != 3 {
		t.Errorf("Expected 3 profiles after reset, got %d", len(profiles))
	}
	if len(orders) != 4 {
		t.Errorf("Expected 4 orders after reset, got %d", len(orders))
	}
	if len(documents) != 4 {
		t.Errorf("Expected 4 documents after reset, got %d", len(documents))
	}

	// Verify specific user data was reset to original
	if users[0].Username != "admin" {
		t.Errorf("Expected first user to be 'admin', got '%s'", users[0].Username)
	}
	if users[1].Username != "user1" {
		t.Errorf("Expected second user to be 'user1', got '%s'", users[1].Username)
	}
	if users[2].Username != "user2" {
		t.Errorf("Expected third user to be 'user2', got '%s'", users[2].Username)
	}
}

// TestResetEndpointMethod tests that only POST is allowed
func TestResetEndpointMethod(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/reset", nil)
		w := httptest.NewRecorder()

		handler := http.HandlerFunc(handleReset)
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Method %s: expected status 405, got %d", method, w.Code)
		}
	}
}
