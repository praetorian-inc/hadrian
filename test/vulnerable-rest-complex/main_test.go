//go:build integration
// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
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

// TestBOLA_CustomerCrossTenant verifies that user2 (ID 3) can read user1's customer record
// (ID 2) including the sensitive ssn field. Also asserts the returned record belongs to a
// DIFFERENT tenant (customer_id != attacker's own id), proving cross-tenant access.
func TestBOLA_CustomerCrossTenant(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	// user2 has ID 3; read user1's record (ID 2) — different tenant
	user2Token := loginToken(t, srv, "user2", "user2pass")

	resp := authGet(t, srv, "/api/customers/2", user2Token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for cross-tenant customer read, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// BOLA confirmed: resource id must be present
	if _, ok := result["id"]; !ok {
		t.Fatal("expected id field in response")
	}

	// Cross-tenant assertion: the returned record belongs to a different customer than user2.
	// user2 is ID 3; the record we fetched is ID 2 (user1).
	returnedID := int(result["id"].(float64))
	const attackerID = 3 // user2's own ID
	if returnedID == attackerID {
		t.Fatalf("expected cross-tenant access (returned id %d == attacker id %d — not BOLA)", returnedID, attackerID)
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

// TestBFLA_AdminDeleteVehicle_AnonymousRejected is a regression test for the
// nil-deref guard: an unauthenticated DELETE must return 401, not panic on a
// nil customer (the intentional BFLA only applies to AUTHENTICATED low-priv
// callers; anonymous requests must be rejected like the sibling handlers).
func TestBFLA_AdminDeleteVehicle_AnonymousRejected(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	resp := authDelete(t, srv, "/api/admin/vehicles/2", "") // empty bearer => nil customer
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous admin delete: expected 401, got %d", resp.StatusCode)
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

// TestBOLA_VehicleRead verifies cross-tenant vehicle read (BOLA). Also asserts that the
// returned vehicle belongs to a different customer (customer_id != attacker's own id).
func TestBOLA_VehicleRead(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	// user2 is customer ID 3; vehicle ID 2 belongs to customer ID 2 (user1)
	user2Token := loginToken(t, srv, "user2", "user2pass")

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

	// Cross-tenant assertion: the vehicle's owner must differ from the attacker.
	// user2 is customer ID 3; vehicle 2 is owned by customer ID 2.
	ownerID := int(result["customer_id"].(float64))
	const attackerID = 3 // user2's own customer ID
	if ownerID == attackerID {
		t.Fatalf("expected cross-tenant access (vehicle owner_id %d == attacker_id %d — not BOLA)", ownerID, attackerID)
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
		// No rate limiting: never a 429.
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("got unexpected 429 on request %d — rate limiting present (not expected)", i)
		}
		// And the endpoint must actually process each attempt (a client-level
		// status), not error out — a 5xx would mean the attempt wasn't handled,
		// which would mask whether rate limiting is truly absent.
		if resp.StatusCode >= http.StatusInternalServerError {
			t.Fatalf("got server error %d on request %d — check-otp did not process the attempt", resp.StatusCode, i)
		}
	}
}

// TestBOLA_OrderRead verifies that user2 (customer ID 3) can read an order belonging to
// user1 (customer ID 2) via GET /api/orders/{id}, proving cross-tenant BOLA on orders.
func TestBOLA_OrderRead(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	// user2 is customer ID 3; order ID 2 belongs to customer ID 2 (user1)
	user2Token := loginToken(t, srv, "user2", "user2pass")

	resp := authGet(t, srv, "/api/orders/2", user2Token)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for cross-tenant order read (BOLA), got %d", resp.StatusCode)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Cross-tenant assertion: order's customer_id must differ from the attacker.
	ownerID := int(result["customer_id"].(float64))
	const attackerID = 3 // user2's own customer ID
	if ownerID == attackerID {
		t.Fatalf("expected cross-tenant access (order owner_id %d == attacker_id %d — not BOLA)", ownerID, attackerID)
	}

	// Sensitive field exposure: card_last4 must be present
	card, _ := result["card_last4"].(string)
	if card == "" {
		t.Fatal("expected card_last4 in order response (sensitive data exposed)")
	}
}

// TestMassAssignment_Order verifies that POST /api/orders honors an injected customer_id
// and an injected price from the request body (mass-assignment vulnerability).
func TestMassAssignment_Order(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	// user2 creates an order but injects victim's customer_id and an arbitrary price
	user2Token := loginToken(t, srv, "user2", "user2pass")

	body, _ := json.Marshal(map[string]interface{}{
		"item":        "Injected Item",
		"customer_id": 2,       // user1's ID — mass assignment
		"price":       0.01,    // attacker-controlled price
		"status":      "completed", // attacker-controlled status
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/orders", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+user2Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for order creation, got %d", resp.StatusCode)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Mass assignment — customer_id must be honored from body (not from the JWT)
	gotCustomerID := int(result["customer_id"].(float64))
	if gotCustomerID != 2 {
		t.Fatalf("expected customer_id=2 (mass assignment), got %d", gotCustomerID)
	}

	// Mass assignment — price must be honored from body
	gotPrice := result["price"].(float64)
	if gotPrice != 0.01 {
		t.Fatalf("expected price=0.01 (mass assignment), got %f", gotPrice)
	}

	// Mass assignment — status must be honored from body
	gotStatus, _ := result["status"].(string)
	if gotStatus != "completed" {
		t.Fatalf("expected status=completed (mass assignment), got %q", gotStatus)
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

// TestConcurrentStoreAccess exercises the in-memory store from multiple goroutines
// simultaneously. Run with -race to verify no data races on the global slices.
// It drives GET reads and POST /api/reset concurrently so the race detector can
// observe any unsynchronised access.
func TestConcurrentStoreAccess(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()

	user1Token := loginToken(t, srv, "user1", "user1pass")
	user2Token := loginToken(t, srv, "user2", "user2pass")

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			if i%3 == 0 {
				// Writer: reset the store
				http.Post(srv.URL+"/api/reset", "application/json", nil) //nolint:errcheck
			} else if i%3 == 1 {
				// Reader: GET vehicle
				req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/vehicles/1", nil)
				req.Header.Set("Authorization", "Bearer "+user1Token)
				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			} else {
				// Reader: GET customer cross-tenant
				req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/customers/2", nil)
				req.Header.Set("Authorization", "Bearer "+user2Token)
				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}
		}()
	}
	wg.Wait()
}

// --- Negative authentication paths (authMiddleware / validateJWT 401s) ---
// These cover the branches that return 401: missing header, malformed token,
// and a validly-signed token missing the customer_id claim (the comma-ok guard
// in validateJWT must return an error rather than panic the handler goroutine).

func rawGet(t *testing.T, srv *httptest.Server, path, authHeader string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestAuth_NoHeaderRejected(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()
	if code := rawGet(t, srv, "/api/customers/1", ""); code != http.StatusUnauthorized {
		t.Errorf("no Authorization header: expected 401, got %d", code)
	}
}

func TestAuth_MalformedTokenRejected(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()
	if code := rawGet(t, srv, "/api/customers/1", "Bearer not-a-jwt"); code != http.StatusUnauthorized {
		t.Errorf("garbage bearer token: expected 401, got %d", code)
	}
}

func TestAuth_MissingCustomerIDClaimRejected(t *testing.T) {
	srv, cleanup := testServer(t)
	defer cleanup()
	// Validly-signed token (correct secret) but WITHOUT a customer_id claim.
	// Exercises the comma-ok guard in validateJWT — must 401, not panic.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"role": "user"})
	signed, err := tok.SignedString(jwtSecret)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	if code := rawGet(t, srv, "/api/customers/1", "Bearer "+signed); code != http.StatusUnauthorized {
		t.Errorf("token missing customer_id claim: expected 401, got %d", code)
	}
}
