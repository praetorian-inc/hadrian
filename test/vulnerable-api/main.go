package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Auth methods
const (
	AuthMethodBearer = "bearer"
	AuthMethodAPIKey = "api_key"
	AuthMethodBasic  = "basic"
	AuthMethodCookie = "cookie"
)

// Data models
type User struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Password  string `json:"-"`
	APIKey    string `json:"-"`
	SessionID string `json:"session_id,omitempty"`
}

type Profile struct {
	ID          int    `json:"id"`
	UserID      int    `json:"user_id"`
	FullName    string `json:"full_name"`
	SSN         string `json:"ssn"` // Sensitive!
	PhoneNumber string `json:"phone_number"`
	Address     string `json:"address"`
}

type Order struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Product   string    `json:"product"`
	Amount    float64   `json:"amount"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type Document struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	IsPrivate bool      `json:"is_private"`
	CreatedAt time.Time `json:"created_at"`
}

// In-memory data store
var (
	users     []User
	profiles  []Profile
	orders    []Order
	documents []Document

	// JWT secret
	jwtSecret = []byte("vulnerable-secret-key-do-not-use-in-production")

	// Auth method (configurable via env)
	authMethod = AuthMethodBearer
)

// Initialize seed data
func initData() {
	// Seed users
	users = []User{
		{ID: 1, Username: "admin", Email: "admin@example.com", Role: "admin", Password: "admin123", APIKey: "admin-api-key-12345", SessionID: "admin-session-xyz789"},
		{ID: 2, Username: "user1", Email: "user1@example.com", Role: "user", Password: "user1pass", APIKey: "user1-api-key-67890", SessionID: "user1-session-abc123"},
		{ID: 3, Username: "user2", Email: "user2@example.com", Role: "user", Password: "user2pass", APIKey: "user2-api-key-abcde", SessionID: "user2-session-def456"},
	}

	// Seed profiles
	profiles = []Profile{
		{ID: 1, UserID: 1, FullName: "Admin User", SSN: "123-45-6789", PhoneNumber: "555-0001", Address: "123 Admin St"},
		{ID: 2, UserID: 2, FullName: "User One", SSN: "234-56-7890", PhoneNumber: "555-0002", Address: "456 User Ave"},
		{ID: 3, UserID: 3, FullName: "User Two", SSN: "345-67-8901", PhoneNumber: "555-0003", Address: "789 User Blvd"},
	}

	// Seed orders
	orders = []Order{
		{ID: 1, UserID: 1, Product: "Admin Widget", Amount: 100.00, Status: "completed", CreatedAt: time.Now().Add(-48 * time.Hour)},
		{ID: 2, UserID: 2, Product: "User Widget A", Amount: 50.00, Status: "pending", CreatedAt: time.Now().Add(-24 * time.Hour)},
		{ID: 3, UserID: 2, Product: "User Widget B", Amount: 75.00, Status: "completed", CreatedAt: time.Now().Add(-12 * time.Hour)},
		{ID: 4, UserID: 3, Product: "User Widget C", Amount: 25.00, Status: "pending", CreatedAt: time.Now().Add(-6 * time.Hour)},
	}

	// Seed documents
	documents = []Document{
		{ID: 1, UserID: 1, Title: "Admin Public Doc", Content: "Public admin content", IsPrivate: false, CreatedAt: time.Now().Add(-72 * time.Hour)},
		{ID: 2, UserID: 1, Title: "Admin Private Doc", Content: "Confidential admin content", IsPrivate: true, CreatedAt: time.Now().Add(-48 * time.Hour)},
		{ID: 3, UserID: 2, Title: "User1 Public Doc", Content: "Public user1 content", IsPrivate: false, CreatedAt: time.Now().Add(-24 * time.Hour)},
		{ID: 4, UserID: 2, Title: "User1 Private Doc", Content: "Private user1 content with SSN", IsPrivate: true, CreatedAt: time.Now().Add(-12 * time.Hour)},
	}
}

// Helper: Extract current user from request context
func getCurrentUser(r *http.Request) *User {
	user, ok := r.Context().Value("user").(*User)
	if !ok {
		return nil
	}
	return user
}

// Helper: Create JWT token
func createJWT(user *User) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Helper: Validate JWT token
func validateJWT(tokenString string) (*User, error) {
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

	userID := int(claims["user_id"].(float64))
	for _, u := range users {
		if u.ID == userID {
			return &u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// Helper: Find user by credentials
func findUserByCredentials(username, password string) *User {
	for _, u := range users {
		if u.Username == username && u.Password == password {
			return &u
		}
	}
	return nil
}

// Helper: Find user by API key
func findUserByAPIKey(apiKey string) *User {
	for _, u := range users {
		if u.APIKey == apiKey {
			return &u
		}
	}
	return nil
}

// Helper: Find user by session ID
func findUserBySessionID(sessionID string) *User {
	for i := range users {
		if users[i].SessionID == sessionID {
			return &users[i]
		}
	}
	return nil
}

// Middleware: CORS
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Middleware: Logging
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] %s %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// Middleware: Authentication (NO AUTHORIZATION - BOLA vulnerability!)
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var user *User
		var err error

		switch authMethod {
		case AuthMethodBearer:
			// JWT Bearer token
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			user, err = validateJWT(tokenString)

		case AuthMethodAPIKey:
			// API Key in X-API-Key header
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			user = findUserByAPIKey(apiKey)
			if user == nil {
				err = fmt.Errorf("invalid API key")
			}

		case AuthMethodBasic:
			// Basic Auth
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Basic ") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			payload, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
			credentials := strings.SplitN(string(payload), ":", 2)
			if len(credentials) != 2 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			user = findUserByCredentials(credentials[0], credentials[1])
			if user == nil {
				err = fmt.Errorf("invalid credentials")
			}

		case AuthMethodCookie:
			// Cookie-based session auth
			cookieHeader := r.Header.Get("Cookie")
			if cookieHeader == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			// Parse session_id from cookie header
			var sessionID string
			for _, part := range strings.Split(cookieHeader, ";") {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "session_id=") {
					sessionID = strings.TrimPrefix(part, "session_id=")
					break
				}
			}
			if sessionID == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			user = findUserBySessionID(sessionID)
			if user == nil {
				err = fmt.Errorf("invalid session")
			}
		}

		if err != nil || user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Log BOLA access attempts (for debugging)
		log.Printf("[BOLA] User %s (ID: %d, Role: %s) accessing %s", user.Username, user.ID, user.Role, r.URL.Path)

		// Store user in context (but don't check authorization!)
		ctx := context.WithValue(r.Context(), "user", user)

		// This is the BOLA vulnerability: we authenticate but don't authorize
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Middleware: Admin only
func adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := getCurrentUser(r)
		if user == nil || user.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// JSON response helper
func jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Handlers: Public endpoints
func handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]string{"status": "healthy"}, http.StatusOK)
}

func handlePublicDocuments(w http.ResponseWriter, r *http.Request) {
	var publicDocs []Document
	for _, doc := range documents {
		if !doc.IsPrivate {
			publicDocs = append(publicDocs, doc)
		}
	}
	jsonResponse(w, publicDocs, http.StatusOK)
}

func handlePublicDocument(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/public/documents/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	for _, doc := range documents {
		if doc.ID == id && !doc.IsPrivate {
			jsonResponse(w, doc, http.StatusOK)
			return
		}
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

// Handlers: Auth endpoints
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

	user := findUserByCredentials(creds.Username, creds.Password)
	if user == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
		},
	}

	// Return appropriate auth credentials based on method
	switch authMethod {
	case AuthMethodBearer:
		token, err := createJWT(user)
		if err != nil {
			http.Error(w, "Failed to create token", http.StatusInternalServerError)
			return
		}
		response["token"] = token
	case AuthMethodAPIKey:
		response["api_key"] = user.APIKey
	case AuthMethodBasic:
		// Basic auth doesn't return credentials, just user info
	case AuthMethodCookie:
		response["session_id"] = user.SessionID
	}

	jsonResponse(w, response, http.StatusOK)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
		"role":     user.Role,
	}, http.StatusOK)
}

// BOLA Vulnerable Handlers: Users
func handleUsers(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	// BOLA VULNERABILITY: No ownership check!
	// Any authenticated user can access any user's data

	for i, user := range users {
		if user.ID == id {
			switch r.Method {
			case http.MethodGet:
				jsonResponse(w, user, http.StatusOK)
			case http.MethodPut:
				var updates User
				if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
					http.Error(w, "Invalid request", http.StatusBadRequest)
					return
				}
				// Update user (keeping ID and password unchanged)
				users[i].Username = updates.Username
				users[i].Email = updates.Email
				users[i].Role = updates.Role
				jsonResponse(w, users[i], http.StatusOK)
			case http.MethodDelete:
				users = append(users[:i], users[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

// BOLA Vulnerable Handlers: Profiles
func handleProfiles(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/profiles/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	// BOLA VULNERABILITY: No ownership check!
	// Any authenticated user can access any profile (including SSNs!)

	for i, profile := range profiles {
		if profile.ID == id {
			switch r.Method {
			case http.MethodGet:
				log.Printf("[BOLA] SSN Exposure: Profile ID %d accessed", id)
				jsonResponse(w, profile, http.StatusOK)
			case http.MethodPut:
				var updates Profile
				if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
					http.Error(w, "Invalid request", http.StatusBadRequest)
					return
				}
				profiles[i].FullName = updates.FullName
				profiles[i].PhoneNumber = updates.PhoneNumber
				profiles[i].Address = updates.Address
				// SSN can also be updated!
				if updates.SSN != "" {
					profiles[i].SSN = updates.SSN
				}
				jsonResponse(w, profiles[i], http.StatusOK)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

// BOLA Vulnerable Handlers: Orders
func handleOrders(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/orders/")

	if idStr == "" {
		// POST /api/orders - Create new order
		if r.Method == http.MethodPost {
			var newOrder Order
			if err := json.NewDecoder(r.Body).Decode(&newOrder); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			newOrder.ID = len(orders) + 1
			newOrder.CreatedAt = time.Now()
			orders = append(orders, newOrder)
			jsonResponse(w, newOrder, http.StatusCreated)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	// BOLA VULNERABILITY: No ownership check!
	// Any authenticated user can access/delete any order

	for i, order := range orders {
		if order.ID == id {
			switch r.Method {
			case http.MethodGet:
				jsonResponse(w, order, http.StatusOK)
			case http.MethodDelete:
				log.Printf("[BOLA] Order deletion: Order ID %d deleted by unauthorized user", id)
				orders = append(orders[:i], orders[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

// BOLA Vulnerable Handlers: Documents
func handleDocuments(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/documents/")

	if idStr == "" {
		// POST /api/documents - Create new document
		if r.Method == http.MethodPost {
			var newDoc Document
			if err := json.NewDecoder(r.Body).Decode(&newDoc); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			newDoc.ID = len(documents) + 1
			newDoc.CreatedAt = time.Now()
			documents = append(documents, newDoc)
			jsonResponse(w, newDoc, http.StatusCreated)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	// BOLA VULNERABILITY: No ownership check!
	// Any authenticated user can access/modify/delete private documents!

	for i, doc := range documents {
		if doc.ID == id {
			switch r.Method {
			case http.MethodGet:
				if doc.IsPrivate {
					log.Printf("[BOLA] Private document access: Doc ID %d accessed", id)
				}
				jsonResponse(w, doc, http.StatusOK)
			case http.MethodPut:
				var updates Document
				if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
					http.Error(w, "Invalid request", http.StatusBadRequest)
					return
				}
				documents[i].Title = updates.Title
				documents[i].Content = updates.Content
				documents[i].IsPrivate = updates.IsPrivate
				jsonResponse(w, documents[i], http.StatusOK)
			case http.MethodDelete:
				documents = append(documents[:i], documents[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

// Admin-only Handlers (properly protected)
func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, users, http.StatusOK)
}

func handleAdminStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"total_users":     len(users),
		"total_profiles":  len(profiles),
		"total_orders":    len(orders),
		"total_documents": len(documents),
	}
	jsonResponse(w, stats, http.StatusOK)
}

// Reset handler (no auth required for testing convenience)
func handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Re-initialize data to original state
	initData()

	log.Printf("Data store reset to initial state")

	jsonResponse(w, map[string]string{
		"message":   "Data store reset to initial state",
		"users":     "3",
		"profiles":  "3",
		"orders":    "4",
		"documents": "4",
	}, http.StatusOK)
}

func main() {
	// Load configuration
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	authMethodEnv := os.Getenv("AUTH_METHOD")
	if authMethodEnv != "" {
		authMethod = authMethodEnv
	}

	// Initialize data
	initData()

	// Print startup info
	fmt.Println("===========================================")
	fmt.Println("VULNERABLE API - FOR TESTING ONLY")
	fmt.Println("===========================================")
	fmt.Printf("Port: %s\n", port)
	fmt.Printf("Auth Method: %s\n", authMethod)
	fmt.Println("\n--- Users ---")
	for _, u := range users {
		fmt.Printf("  %s (ID: %d, Role: %s)\n", u.Username, u.ID, u.Role)
		fmt.Printf("    Password: %s\n", u.Password)
		fmt.Printf("    API Key: %s\n", u.APIKey)
		fmt.Printf("    Session ID: %s\n", u.SessionID)
	}
	fmt.Println("\n--- Vulnerable Endpoints (BOLA) ---")
	fmt.Println("  GET/PUT/DELETE /api/users/{id}")
	fmt.Println("  GET/PUT        /api/profiles/{id}")
	fmt.Println("  GET/POST/DELETE /api/orders/{id}")
	fmt.Println("  GET/POST/PUT/DELETE /api/documents/{id}")
	fmt.Println("\n--- Protected Endpoints (Admin Only) ---")
	fmt.Println("  GET /api/admin/users")
	fmt.Println("  GET /api/admin/stats")
	fmt.Println("\n--- Reset Endpoint ---")
	fmt.Println("  POST /api/reset - Reset data to initial state")
	fmt.Println("===========================================")
	fmt.Println()

	// Setup routes
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/public/documents", handlePublicDocuments)
	mux.HandleFunc("/api/public/documents/", handlePublicDocument)
	mux.HandleFunc("/api/reset", handleReset)

	// Auth routes
	mux.HandleFunc("/api/auth/login", handleLogin)
	mux.Handle("/api/auth/me", authMiddleware(http.HandlerFunc(handleMe)))

	// BOLA vulnerable routes (authenticated but NO authorization)
	mux.Handle("/api/users/", authMiddleware(http.HandlerFunc(handleUsers)))
	mux.Handle("/api/profiles/", authMiddleware(http.HandlerFunc(handleProfiles)))
	mux.Handle("/api/orders/", authMiddleware(http.HandlerFunc(handleOrders)))
	mux.Handle("/api/orders", authMiddleware(http.HandlerFunc(handleOrders)))
	mux.Handle("/api/documents/", authMiddleware(http.HandlerFunc(handleDocuments)))
	mux.Handle("/api/documents", authMiddleware(http.HandlerFunc(handleDocuments)))

	// Admin-only routes (properly protected)
	mux.Handle("/api/admin/users", authMiddleware(adminMiddleware(http.HandlerFunc(handleAdminUsers))))
	mux.Handle("/api/admin/stats", authMiddleware(adminMiddleware(http.HandlerFunc(handleAdminStats))))

	// Apply middleware
	handler := corsMiddleware(loggingMiddleware(mux))

	// Start server
	addr := ":" + port
	log.Printf("Starting vulnerable API server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}
