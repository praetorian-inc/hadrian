// INTENTIONALLY INSECURE - FOR TESTING ONLY
// This server is a deliberate multi-resource REST target for Hadrian security testing.
// It mirrors the shape of OWASP crAPI (vehicles + mechanics + orders + customers) with
// intentional cross-tenant authorization bugs.  DO NOT deploy to production.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// -----------------------------------------------------------------------
// Data models
// -----------------------------------------------------------------------

type Customer struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	Password    string `json:"-"`
	SSN         string `json:"ssn"`          // SENSITIVE — exposed by BOLA + excessive-data
	PaymentCard string `json:"payment_card"` // SENSITIVE — exposed by BOLA + excessive-data
}

type Vehicle struct {
	ID         int    `json:"id"`
	CustomerID int    `json:"customer_id"`
	VIN        string `json:"vin"`
	Location   string `json:"location"`
}

type Order struct {
	ID         int     `json:"id"`
	CustomerID int     `json:"customer_id"`
	Item       string  `json:"item"`
	Price      float64 `json:"price"`
	Status     string  `json:"status"`
	CardLast4  string  `json:"card_last4"` // SENSITIVE
}

type ServiceRequest struct {
	ID         int    `json:"id"`
	CustomerID int    `json:"customer_id"`
	VehicleID  int    `json:"vehicle_id"`
	Problem    string `json:"problem"`
	ReportID   string `json:"report_id"`
}

// Dashboard is the per-customer summary returned by GET /api/dashboard.
// It intentionally exposes sensitive fields (excessive-data-exposure target).
type Dashboard struct {
	CustomerID  int    `json:"customer_id"`
	VehicleID   int    `json:"vehicle_id"`
	OrderID     int    `json:"order_id"`
	Role        string `json:"role"`
	SSN         string `json:"ssn"`          // SENSITIVE
	PaymentCard string `json:"payment_card"` // SENSITIVE
}

// -----------------------------------------------------------------------
// In-memory data store
// -----------------------------------------------------------------------

var (
	mu              sync.Mutex // guards customers, vehicles, orders, serviceRequests
	customers       []Customer
	vehicles        []Vehicle
	orders          []Order
	serviceRequests []ServiceRequest

	// JWT secret — INTENTIONALLY INSECURE: this is an intentionally vulnerable test server
	jwtSecret = []byte("vulnerable-rest-complex-secret-do-not-use-in-production")
)

// -----------------------------------------------------------------------
// Seed data
// -----------------------------------------------------------------------

func initData() {
	// Seed customers — INTENTIONALLY INSECURE: hardcoded credentials for this vulnerable test server.
	// These are NOT real credentials. This server exists solely to be a test target for Hadrian.
	customers = []Customer{
		{ID: 1, Username: "admin", Email: "admin@example.com", Role: "admin", Password: "admin123", SSN: "111-11-1111", PaymentCard: "4111111111111111"},
		{ID: 2, Username: "user1", Email: "user1@example.com", Role: "user", Password: "user1pass", SSN: "222-22-2222", PaymentCard: "4222222222222222"},
		{ID: 3, Username: "user2", Email: "user2@example.com", Role: "user", Password: "user2pass", SSN: "333-33-3333", PaymentCard: "4333333333333333"},
		{ID: 4, Username: "mechanic1", Email: "mechanic1@example.com", Role: "mechanic", Password: "mech1pass", SSN: "444-44-4444", PaymentCard: "4444444444444444"},
	}

	// Each customer gets a vehicle
	vehicles = []Vehicle{
		{ID: 1, CustomerID: 1, VIN: "1HGCM82633A000001", Location: "Garage A"},
		{ID: 2, CustomerID: 2, VIN: "1HGCM82633A000002", Location: "Garage B"},
		{ID: 3, CustomerID: 3, VIN: "1HGCM82633A000003", Location: "Garage C"},
		{ID: 4, CustomerID: 4, VIN: "1HGCM82633A000004", Location: "Shop"},
	}

	// Each customer has at least one order
	orders = []Order{
		{ID: 1, CustomerID: 1, Item: "Premium Plan", Price: 199.99, Status: "completed", CardLast4: "1111"},
		{ID: 2, CustomerID: 2, Item: "Basic Plan", Price: 49.99, Status: "pending", CardLast4: "2222"},
		{ID: 3, CustomerID: 2, Item: "Add-on Pack", Price: 19.99, Status: "completed", CardLast4: "2222"},
		{ID: 4, CustomerID: 3, Item: "Basic Plan", Price: 49.99, Status: "pending", CardLast4: "3333"},
		{ID: 5, CustomerID: 4, Item: "Tool Kit", Price: 99.99, Status: "completed", CardLast4: "4444"},
	}

	serviceRequests = []ServiceRequest{}
}

// -----------------------------------------------------------------------
// JWT helpers
// -----------------------------------------------------------------------

func createJWT(c *Customer) (string, error) {
	claims := jwt.MapClaims{
		"customer_id": c.ID,
		"username":    c.Username,
		"role":        c.Role,
		"exp":         time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateJWT(tokenString string) (*Customer, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	// Guard the claim cast (comma-ok) — a validly-signed token with a missing
	// or non-numeric customer_id must error, not panic the handler goroutine.
	// Mirrors the guard in vulnerable-graphql's parseJWT.
	cidF, ok := claims["customer_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid customer_id claim")
	}
	customerID := int(cidF)
	mu.Lock()
	defer mu.Unlock()
	for _, c := range customers {
		if c.ID == customerID {
			return &c, nil
		}
	}
	return nil, fmt.Errorf("customer not found")
}

func findCustomerByCredentials(username, password string) *Customer {
	mu.Lock()
	defer mu.Unlock()
	for _, c := range customers {
		if c.Username == username && c.Password == password {
			return &c
		}
	}
	return nil
}

// -----------------------------------------------------------------------
// Context helpers
// -----------------------------------------------------------------------

type contextKey string

const ctxCustomer contextKey = "customer"

func getCustomer(r *http.Request) *Customer {
	c, _ := r.Context().Value(ctxCustomer).(*Customer)
	return c
}

// -----------------------------------------------------------------------
// Middleware
// -----------------------------------------------------------------------

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] %s %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// authMiddleware authenticates but does NO authorization — this is the BOLA vulnerability.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		customer, err := validateJWT(tokenString)
		if err != nil || customer == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Log BOLA access attempts (for debugging)
		log.Printf("[BOLA] Customer %s (ID: %d, Role: %s) accessing %s", customer.Username, customer.ID, customer.Role, r.URL.Path)
		// Store customer in context (but don't check authorization!)
		ctx := context.WithValue(r.Context(), ctxCustomer, customer)
		// This is the BOLA vulnerability: we authenticate but don't authorize
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// adminMiddleware is PROPERLY protected — used as a negative control.
func adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := getCustomer(r)
		if c == nil || c.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// -----------------------------------------------------------------------
// JSON helper
// -----------------------------------------------------------------------

func jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// -----------------------------------------------------------------------
// Public / utility handlers
// -----------------------------------------------------------------------

func handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]string{"status": "healthy"}, http.StatusOK)
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mu.Lock()
	initData()
	mu.Unlock()
	log.Printf("Data store reset to initial state")
	jsonResponse(w, map[string]string{
		"message":   "Data store reset to initial state",
		"customers": "4",
		"vehicles":  "4",
		"orders":    "5",
	}, http.StatusOK)
}

// -----------------------------------------------------------------------
// Auth handlers
// -----------------------------------------------------------------------

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	customer := findCustomerByCredentials(creds.Username, creds.Password)
	if customer == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	token, err := createJWT(customer)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"token": token,
		"customer": map[string]interface{}{
			"id":       customer.ID,
			"username": customer.Username,
			"email":    customer.Email,
			"role":     customer.Role,
		},
	}, http.StatusOK)
}

// handleCheckOTP — NO RATE LIMITING: accepts {email, otp, password} without any throttle.
// This is the rate-limit test target mirroring crAPI's /community/api/v2/user/check-otp.
func handleCheckOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Email    string `json:"email"`
		OTP      string `json:"otp"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	// NO RATE LIMITING VULNERABILITY: We never throttle this endpoint.
	if req.OTP == "000000" {
		jsonResponse(w, map[string]string{"message": "OTP verified"}, http.StatusOK)
		return
	}
	http.Error(w, "Invalid OTP", http.StatusBadRequest)
}

// -----------------------------------------------------------------------
// Dashboard handler (excessive data exposure target)
// -----------------------------------------------------------------------

// handleDashboard returns the current customer's own dashboard, including sensitive fields.
// The excessive data exposure is intentional: role, ssn, and payment_card are returned.
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c := getCustomer(r)
	if c == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Find this customer's vehicle and order IDs
	mu.Lock()
	vehicleID := 0
	for _, v := range vehicles {
		if v.CustomerID == c.ID {
			vehicleID = v.ID
			break
		}
	}
	orderID := 0
	for _, o := range orders {
		if o.CustomerID == c.ID {
			orderID = o.ID
			break
		}
	}
	mu.Unlock()

	// EXCESSIVE DATA EXPOSURE: returns ssn, payment_card, and role in the dashboard
	jsonResponse(w, Dashboard{
		CustomerID:  c.ID,
		VehicleID:   vehicleID,
		OrderID:     orderID,
		Role:        c.Role,
		SSN:         c.SSN,
		PaymentCard: c.PaymentCard,
	}, http.StatusOK)
}

// -----------------------------------------------------------------------
// Customer handlers (BOLA + excessive data exposure)
// -----------------------------------------------------------------------

func handleCustomer(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/customers/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	var found *Customer
	for i, c := range customers {
		if c.ID == id {
			found = &customers[i]
			break
		}
	}
	mu.Unlock()
	if found != nil {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// BOLA VULNERABILITY: No ownership check!
		// EXCESSIVE DATA EXPOSURE: Returns ssn, payment_card, role to any authenticated user.
		log.Printf("[BOLA] Customer data exposure: Customer ID %d accessed by another user", id)
		jsonResponse(w, *found, http.StatusOK)
		return
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

// -----------------------------------------------------------------------
// Vehicle handlers
// -----------------------------------------------------------------------

func handleVehicle(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/vehicles/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	idx := -1
	for i, v := range vehicles {
		if v.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		mu.Unlock()
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		// BOLA VULNERABILITY: No ownership check!
		// Any authenticated customer can read any vehicle (vin, location).
		v := vehicles[idx]
		mu.Unlock()
		log.Printf("[BOLA] Vehicle read: Vehicle ID %d accessed", id)
		jsonResponse(w, v, http.StatusOK)

	case http.MethodPut:
		var updates map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			mu.Unlock()
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		// MASS ASSIGNMENT VULNERABILITY: honors id, customer_id, owner_id from body.
		// An attacker can inject a victim's vehicle ID or reassign ownership.
		log.Printf("[MASS-ASSIGNMENT] Vehicle update with body fields: %v", updates)
		if val, ok := updates["id"]; ok {
			if fv, ok := val.(float64); ok {
				vehicles[idx].ID = int(fv)
			}
		}
		if val, ok := updates["customer_id"]; ok {
			if fv, ok := val.(float64); ok {
				vehicles[idx].CustomerID = int(fv)
			}
		}
		if val, ok := updates["owner_id"]; ok {
			if fv, ok := val.(float64); ok {
				vehicles[idx].CustomerID = int(fv)
			}
		}
		if val, ok := updates["vin"]; ok {
			if sv, ok := val.(string); ok {
				vehicles[idx].VIN = sv
			}
		}
		if val, ok := updates["location"]; ok {
			if sv, ok := val.(string); ok {
				vehicles[idx].Location = sv
			}
		}
		v := vehicles[idx]
		mu.Unlock()
		jsonResponse(w, v, http.StatusOK)

	default:
		mu.Unlock()
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// -----------------------------------------------------------------------
// Order handlers
// -----------------------------------------------------------------------

func handleOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	c := getCustomer(r)

	mu.Lock()
	newOrder := Order{
		ID:         len(orders) + 1,
		CustomerID: c.ID,
		Status:     "pending",
	}

	// MASS ASSIGNMENT VULNERABILITY: honors customer_id, price, status from the request body.
	if val, ok := body["customer_id"]; ok {
		if fv, ok := val.(float64); ok {
			newOrder.CustomerID = int(fv) // attacker can set arbitrary customer_id
		}
	}
	if val, ok := body["item"]; ok {
		if sv, ok := val.(string); ok {
			newOrder.Item = sv
		}
	}
	if val, ok := body["price"]; ok {
		if fv, ok := val.(float64); ok {
			newOrder.Price = fv // attacker can set arbitrary price
		}
	}
	if val, ok := body["status"]; ok {
		if sv, ok := val.(string); ok {
			newOrder.Status = sv // attacker can set arbitrary status
		}
	}
	if val, ok := body["card_last4"]; ok {
		if sv, ok := val.(string); ok {
			newOrder.CardLast4 = sv
		}
	}

	log.Printf("[MASS-ASSIGNMENT] Order created with body fields: customer_id=%d status=%s price=%f", newOrder.CustomerID, newOrder.Status, newOrder.Price)
	orders = append(orders, newOrder)
	mu.Unlock()
	jsonResponse(w, newOrder, http.StatusCreated)
}

func handleOrder(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/orders/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mu.Lock()
	var found *Order
	for i, o := range orders {
		if o.ID == id {
			found = &orders[i]
			break
		}
	}
	mu.Unlock()
	if found != nil {
		// BOLA VULNERABILITY: No ownership check!
		// Any authenticated customer can read any order (amount, card_last4).
		log.Printf("[BOLA] Order read: Order ID %d accessed", id)
		jsonResponse(w, *found, http.StatusOK)
		return
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

// -----------------------------------------------------------------------
// Mechanic service-request handler (BFLA)
// -----------------------------------------------------------------------

// handleServiceRequest — BFLA VULNERABILITY: mechanic-only function but NO role check.
// Any authenticated user can submit a mechanic service request.
func handleServiceRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c := getCustomer(r)
	if c == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		VehicleID int    `json:"vehicle_id"`
		Problem   string `json:"problem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// BFLA VULNERABILITY: We should check c.Role == "mechanic" but we don't.
	log.Printf("[BFLA] Service request submitted by %s (role: %s) — mechanic-only endpoint!", c.Username, c.Role)

	mu.Lock()
	sr := ServiceRequest{
		ID:         len(serviceRequests) + 1,
		CustomerID: c.ID,
		VehicleID:  req.VehicleID,
		Problem:    req.Problem,
		ReportID:   fmt.Sprintf("RPT-%05d", len(serviceRequests)+1),
	}
	serviceRequests = append(serviceRequests, sr)
	mu.Unlock()
	jsonResponse(w, sr, http.StatusOK)
}

// -----------------------------------------------------------------------
// Admin handlers
// -----------------------------------------------------------------------

// handleAdminDeleteVehicle — BFLA VULNERABILITY: admin-only delete but NO role check.
// Any authenticated user can delete any vehicle via this admin endpoint.
func handleAdminDeleteVehicle(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/vehicles/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	c := getCustomer(r)
	// BFLA VULNERABILITY: We should check c.Role == "admin" but we don't.
	log.Printf("[BFLA] Admin delete vehicle ID %d by %s (role: %s) — admin-only endpoint!", id, c.Username, c.Role)

	mu.Lock()
	found := false
	for i, v := range vehicles {
		if v.ID == id {
			vehicles = append(vehicles[:i], vehicles[i+1:]...)
			found = true
			break
		}
	}
	mu.Unlock()
	if found {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

// handleAdminReports — PROPERLY protected admin endpoint (negative control).
// Returns 403 for non-admin users.
func handleAdminReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mu.Lock()
	reports := make([]ServiceRequest, len(serviceRequests))
	copy(reports, serviceRequests)
	mu.Unlock()
	jsonResponse(w, map[string]interface{}{
		"reports": reports,
		"total":   len(reports),
	}, http.StatusOK)
}

// -----------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8888"
	}

	initData()

	fmt.Println("===========================================")
	fmt.Println("VULNERABLE REST COMPLEX - FOR TESTING ONLY")
	fmt.Println("===========================================")
	fmt.Printf("Port: %s\n", port)
	fmt.Println("\n--- Seed Customers ---")
	for _, c := range customers {
		fmt.Printf("  %s (ID: %d, Role: %s)\n", c.Username, c.ID, c.Role)
		fmt.Printf("    Password: %s\n", c.Password)
	}
	fmt.Println("\n--- Vulnerable Endpoints (BOLA) ---")
	fmt.Println("  GET  /api/customers/{id}  (BOLA + EXCESSIVE DATA: returns ssn, payment_card, role)")
	fmt.Println("  GET  /api/vehicles/{id}   (BOLA: any authed customer reads any vehicle)")
	fmt.Println("  GET  /api/orders/{id}     (BOLA: read any order amount + card_last4)")
	fmt.Println("\n--- Vulnerable Endpoints (Mass Assignment) ---")
	fmt.Println("  PUT  /api/vehicles/{id}   (MASS ASSIGNMENT: honors id/customer_id/owner_id from body)")
	fmt.Println("  POST /api/orders          (MASS ASSIGNMENT: honors customer_id/price/status from body)")
	fmt.Println("\n--- Vulnerable Endpoints (BFLA) ---")
	fmt.Println("  POST   /api/mechanic/service-requests  (BFLA: mechanic-only but no role check)")
	fmt.Println("  DELETE /api/admin/vehicles/{id}        (BFLA: admin-only but no role check)")
	fmt.Println("\n--- Rate-Limit Vulnerable ---")
	fmt.Println("  POST /api/auth/check-otp  (NO RATE LIMITING)")
	fmt.Println("\n--- Excessive Data Exposure ---")
	fmt.Println("  GET  /api/dashboard       (returns role, ssn, payment_card)")
	fmt.Println("\n--- Properly Protected (Admin Only) ---")
	fmt.Println("  GET  /api/admin/reports   (returns 403 for non-admin)")
	fmt.Println("\n--- Reset ---")
	fmt.Println("  POST /api/reset")
	fmt.Println("===========================================")
	fmt.Println()

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/reset", handleReset)

	// Auth
	mux.HandleFunc("/api/auth/login", handleLogin)
	mux.HandleFunc("/api/auth/check-otp", handleCheckOTP) // NO RATE LIMITING

	// Authenticated (BOLA + excessive data)
	mux.Handle("/api/dashboard", authMiddleware(http.HandlerFunc(handleDashboard)))
	mux.Handle("/api/customers/", authMiddleware(http.HandlerFunc(handleCustomer)))
	mux.Handle("/api/vehicles/", authMiddleware(http.HandlerFunc(handleVehicle)))
	mux.Handle("/api/orders/", authMiddleware(http.HandlerFunc(handleOrder)))
	mux.Handle("/api/orders", authMiddleware(http.HandlerFunc(handleOrders)))

	// Mechanic BFLA (authenticated but no role check)
	mux.Handle("/api/mechanic/service-requests", authMiddleware(http.HandlerFunc(handleServiceRequest)))

	// Admin BFLA endpoints (authenticated but NO role check on delete — INTENTIONAL)
	mux.Handle("/api/admin/vehicles/", authMiddleware(http.HandlerFunc(handleAdminDeleteVehicle)))

	// Admin properly-protected endpoint (negative control)
	mux.Handle("/api/admin/reports", authMiddleware(adminMiddleware(http.HandlerFunc(handleAdminReports))))

	handler := loggingMiddleware(mux)
	// Bind loopback only (matches vulnerable-graphql): this is an intentionally
	// vulnerable target, so it must not be reachable off-host. All callers use
	// http://localhost.
	addr := "127.0.0.1:" + port
	log.Printf("Starting vulnerable-rest-complex server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}
