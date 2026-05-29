package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// testServer creates an httptest.Server wired up to the same mux as main().
func testServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	initData()

	mux := http.NewServeMux()

	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/reset", handleReset)
	mux.HandleFunc("/api/auth/login", handleLogin)
	mux.HandleFunc("/api/auth/check-otp", handleCheckOTP)

	mux.Handle("/api/dashboard", authMiddleware(http.HandlerFunc(handleDashboard)))
	mux.Handle("/api/customers/", authMiddleware(http.HandlerFunc(handleCustomer)))
	mux.Handle("/api/vehicles/", authMiddleware(http.HandlerFunc(handleVehicle)))
	mux.Handle("/api/orders/", authMiddleware(http.HandlerFunc(handleOrder)))
	mux.Handle("/api/orders", authMiddleware(http.HandlerFunc(handleOrders)))

	mux.Handle("/api/mechanic/service-requests", authMiddleware(http.HandlerFunc(handleServiceRequest)))
	mux.Handle("/api/admin/vehicles/", authMiddleware(http.HandlerFunc(handleAdminDeleteVehicle)))
	mux.Handle("/api/admin/reports", authMiddleware(adminMiddleware(http.HandlerFunc(handleAdminReports))))

	srv := httptest.NewServer(mux)
	return srv, func() { srv.Close() }
}

// loginToken obtains a JWT for the given username/password.
func loginToken(t *testing.T, srv *httptest.Server, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login expected 200, got %d", resp.StatusCode)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	token, _ := result["token"].(string)
	if token == "" {
		t.Fatal("login returned empty token")
	}
	return token
}

// authGet performs a GET with a Bearer token.
func authGet(t *testing.T, srv *httptest.Server, path, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	return resp
}

// authDelete performs a DELETE with a Bearer token.
func authDelete(t *testing.T, srv *httptest.Server, path, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s failed: %v", path, err)
	}
	return resp
}

// authPut performs a PUT with a Bearer token and JSON body.
func authPut(t *testing.T, srv *httptest.Server, path, token string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s failed: %v", path, err)
	}
	return resp
}

// TestHealth verifies /health returns {"status":"healthy"}.
func TestHealth(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "healthy" {
		t.Fatalf("expected status=healthy, got %q", result["status"])
	}
}

// TestLoginReturnsJWT verifies POST /api/auth/login returns a non-empty JWT.
func TestLoginReturnsJWT(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	token := loginToken(t, srv, "user1", "user1pass")
	if len(token) < 20 {
		t.Fatalf("token too short: %q", token)
	}
}

// TestBOLA_CustomerCrossTenant verifies that user2 (lower priv, ID 3) can read
// user1's customer record (ID 2) including the sensitive ssn field.
// This is the BOLA + excessive-data-exposure vulnerability.
func TestBOLA_CustomerCrossTenant(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	user2Token := loginToken(t, srv, "user2", "user2pass")

	// user2 reads user1's customer record (id=2) — should succeed (BOLA)
	resp := authGet(t, srv, "/api/customers/2", user2Token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for cross-tenant customer read, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// BOLA confirmed: user2 read user1's data
	if _, ok := result["id"]; !ok {
		t.Fatal("expected id field in response")
	}

	// Excessive data exposure: ssn must be present
	ssn, _ := result["ssn"].(string)
	if ssn == "" {
		t.Fatal("expected ssn in response (excessive data exposure)")
	}

	// Excessive data exposure: payment_card must be present
	card, _ := result["payment_card"].(string)
	if card == "" {
		t.Fatal("expected payment_card in response (excessive data exposure)")
	}
}

// TestMassAssignment_Vehicle verifies that PUT /api/vehicles/{id} accepts customer_id
// from the request body and stores it (mass assignment vulnerability).
func TestMassAssignment_Vehicle(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	// user2 (customer_id=3) targets user1's vehicle (id=2)
	user2Token := loginToken(t, srv, "user2", "user2pass")

	// Inject victim's customer_id into body for user2's vehicle update
	body := map[string]interface{}{
		"customer_id": 999, // arbitrary reassignment
		"vin":         "INJECTED_VIN",
	}
	resp := authPut(t, srv, "/api/vehicles/2", user2Token, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for mass assignment PUT, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Verify customer_id was honored from body (mass assignment confirmed)
	cid, _ := result["customer_id"].(float64)
	if int(cid) != 999 {
		t.Fatalf("expected customer_id=999 (mass assignment), got %v", result["customer_id"])
	}
}

// TestBFLA_AdminDeleteVehicle verifies that a non-admin user (user2) can delete
// a vehicle via the admin endpoint, and that GET /api/vehicles/{id} then returns 404.
func TestBFLA_AdminDeleteVehicle(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	user2Token := loginToken(t, srv, "user2", "user2pass")
	user1Token := loginToken(t, srv, "user1", "user1pass")

	// user2 deletes user1's vehicle (id=2) via the admin endpoint — BFLA
	resp := authDelete(t, srv, "/api/admin/vehicles/2", user2Token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for BFLA admin delete, got %d", resp.StatusCode)
	}

	// Verify the vehicle is gone: user1 should now get 404
	resp2 := authGet(t, srv, "/api/vehicles/2", user1Token)
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after admin delete, got %d", resp2.StatusCode)
	}
}

// TestAdminReports_ForbiddenForNonAdmin verifies that GET /api/admin/reports
// returns 403 for a non-admin user (negative control).
func TestAdminReports_ForbiddenForNonAdmin(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	user1Token := loginToken(t, srv, "user1", "user1pass")

	resp := authGet(t, srv, "/api/admin/reports", user1Token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin admin/reports, got %d", resp.StatusCode)
	}
}

// TestAdminReports_AllowedForAdmin verifies the same endpoint works for admin.
func TestAdminReports_AllowedForAdmin(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	adminToken := loginToken(t, srv, "admin", "admin123")

	resp := authGet(t, srv, "/api/admin/reports", adminToken)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for admin admin/reports, got %d", resp.StatusCode)
	}
}

// TestBOLA_VehicleRead verifies cross-tenant vehicle read (BOLA).
func TestBOLA_VehicleRead(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	user2Token := loginToken(t, srv, "user2", "user2pass")

	// user2 reads user1's vehicle (id=2)
	resp := authGet(t, srv, "/api/vehicles/2", user2Token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for cross-tenant vehicle read, got %d", resp.StatusCode)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["vin"] == nil {
		t.Fatal("expected vin in response")
	}
}

// TestDashboard_ExcessiveData verifies GET /api/dashboard returns sensitive fields.
func TestDashboard_ExcessiveData(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	user1Token := loginToken(t, srv, "user1", "user1pass")
	resp := authGet(t, srv, "/api/dashboard", user1Token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for dashboard, got %d", resp.StatusCode)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	for _, field := range []string{"role", "ssn", "payment_card", "vehicle_id", "order_id"} {
		if result[field] == nil {
			t.Fatalf("expected field %s in dashboard response (excessive data exposure)", field)
		}
	}
}

// TestReset verifies POST /api/reset re-seeds the store.
func TestReset(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	// Delete a vehicle first
	user2Token := loginToken(t, srv, "user2", "user2pass")
	authDelete(t, srv, "/api/admin/vehicles/1", user2Token)

	// Reset
	resp, err := http.Post(srv.URL+"/api/reset", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for reset, got %d", resp.StatusCode)
	}

	// Vehicle 1 should be back
	adminToken := loginToken(t, srv, "admin", "admin123")
	resp2 := authGet(t, srv, "/api/vehicles/1", adminToken)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected vehicle 1 restored after reset, got %d", resp2.StatusCode)
	}
}

// TestCheckOTP_NoRateLimit verifies POST /api/auth/check-otp accepts requests
// without any rate limiting (submits 10 rapid requests, all accepted).
func TestCheckOTP_NoRateLimit(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	for i := 0; i < 10; i++ {
		body, _ := json.Marshal(map[string]string{
			"email":    "user1@example.com",
			"otp":      fmt.Sprintf("%04d", i),
			"password": "newpass",
		})
		resp, err := http.Post(srv.URL+"/api/auth/check-otp", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("check-otp request %d failed: %v", i, err)
		}
		resp.Body.Close()
		// Any 200 or 400 is fine — we just confirm no 429 is returned
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("got unexpected 429 on request %d — rate limiting present (not expected)", i)
		}
	}
}

// TestBFLA_ServiceRequest verifies that a non-mechanic user can submit a service request.
func TestBFLA_ServiceRequest(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	// user1 is a regular user, not a mechanic
	user1Token := loginToken(t, srv, "user1", "user1pass")

	body, _ := json.Marshal(map[string]interface{}{
		"vehicle_id": 2,
		"problem":    "Engine noise",
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/mechanic/service-requests", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+user1Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for BFLA service request, got %d", resp.StatusCode)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["report_id"] == nil {
		t.Fatal("expected report_id in response")
	}
}
