//go:build integration

package runner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// In-process vulnerable REST fixture (no Docker, no external target)
// =============================================================================
//
// This file provides an httptest-backed REST API that intentionally seeds the
// OWASP API vulnerabilities Hadrian's templates detect — BOLA/IDOR (API1),
// broken authentication (API2), excessive data exposure / BOPLA (API3), and
// BFLA (API5). Integration tests run the real templates in templates/rest/
// against this server, so detection is exercised end-to-end without launching
// any container.
//
// Authentication uses opaque static bearer tokens (no JWT dependency): each
// token simply maps to a seeded user. The vulnerabilities live in the
// (missing) authorization checks, which is what the templates probe.

// fixtureTokens maps bearer tokens to the user ID + role they authenticate as.
// admin is the highest-privilege victim; user2 is the lowest-privilege attacker.
var fixtureTokens = map[string]struct {
	userID int
	role   string
}{
	"admin-token": {userID: 1, role: "admin"},
	"user1-token": {userID: 2, role: "user"},
	"user2-token": {userID: 3, role: "user"},
}

// fixtureUser returns the user a bearer token authenticates as, or ok=false.
func fixtureUser(r *http.Request) (userID int, role string, ok bool) {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		return 0, "", false
	}
	u, found := fixtureTokens[strings.TrimPrefix(authz, "Bearer ")]
	return u.userID, u.role, found
}

func fixtureJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// newVulnerableRESTServer builds the seeded vulnerable REST API and returns a
// running httptest server. The caller is responsible for nothing — cleanup is
// registered via t.Cleanup.
func newVulnerableRESTServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(vulnerableRESTHandler())
	t.Cleanup(server.Close)
	return server
}

// newSecuredRESTServer is the NON-vulnerable control: it enforces authorization
// on every endpoint the spec declares — missing token → 401, present token →
// 403 (deny, since the attacker is never the resource owner / not admin). The
// same templates that fire against the vulnerable fixture must produce ZERO
// findings here, proving the detection assertions are differential rather than
// unconditional.
func newSecuredRESTServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := fixtureUser(r); !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	return server
}

// vulnerableRESTHandler builds the seeded vulnerable REST API as an http.Handler
// so callers can wrap it (e.g. to capture request headers) before serving.
func vulnerableRESTHandler() http.Handler {
	mux := http.NewServeMux()

	// requireAuth wraps a handler so it rejects requests without a valid token.
	// This models endpoints that DO enforce authentication but NOT authorization
	// (the BOLA/BFLA bugs live in the handler returning data regardless of owner).
	requireAuth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if _, _, ok := fixtureUser(r); !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	// API1 — BOLA/IDOR: any authenticated user can read any user record.
	mux.HandleFunc("/api/users/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"id": pathID(r, "/api/users/"), "username": "victim", "email": "victim@example.com", "role": "admin",
		})
	}))

	// API3 — Excessive data exposure / BOPLA: profile leaks SSN to any authed user.
	mux.HandleFunc("/api/profiles/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"id": pathID(r, "/api/profiles/"), "user_id": 1, "full_name": "Victim User",
			"ssn": "123-45-6789", "phone_number": "555-0001", "credit_card": "4111111111111111",
		})
	}))

	// API1 — BOLA on orders (read/delete with no ownership check).
	mux.HandleFunc("/api/orders/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"id": pathID(r, "/api/orders/"), "user_id": 1, "product": "Victim Widget", "amount": 100.0,
		})
	}))

	// API1 — BOLA on documents (read/update/delete private docs with no check).
	mux.HandleFunc("/api/documents/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"id": pathID(r, "/api/documents/"), "user_id": 1, "title": "Private Doc",
			"content": "confidential", "is_private": true,
		})
	}))

	// API5 — BFLA: admin endpoint reachable by ANY authenticated user (no role check).
	mux.HandleFunc("/api/admin/users", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		fixtureJSON(w, http.StatusOK, []map[string]interface{}{
			{"id": 1, "username": "admin", "role": "admin"},
		})
	}))

	// API2 — Broken authentication: this endpoint is declared as requiring auth in
	// the spec, but the handler serves sensitive config WITHOUT any token.
	mux.HandleFunc("/api/internal/config", func(w http.ResponseWriter, r *http.Request) {
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"database_host": "db.internal.example.com", "debug_mode": true,
			"secret_key_ref": "vault://secrets/api-key",
		})
	})

	return mux
}

// pathID extracts the trailing path segment (the resource id) after prefix.
func pathID(r *http.Request, prefix string) string {
	return strings.TrimPrefix(r.URL.Path, prefix)
}

// =============================================================================
// Spec / roles / auth fixtures (written to a temp dir, pointed at the server)
// =============================================================================

// fixtureSpecTemplate is an OpenAPI 3.0 spec describing the seeded endpoints.
// %s is replaced with the running server URL. Every endpoint declares bearer
// security so the templates treat them as authenticated endpoints.
const fixtureSpecTemplate = `openapi: "3.0.0"
info:
  title: Vulnerable Test API
  version: "1.0.0"
servers:
  - url: "%s"
paths:
  /api/users/{id}:
    get:
      summary: Get user by ID
      security: [{bearerAuth: []}]
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: OK}}
  /api/profiles/{id}:
    get:
      summary: Get profile by ID
      security: [{bearerAuth: []}]
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: OK}}
  /api/orders/{id}:
    get:
      summary: Get order by ID
      security: [{bearerAuth: []}]
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: OK}}
    delete:
      summary: Delete order by ID
      security: [{bearerAuth: []}]
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"204": {description: No Content}}
  /api/documents/{id}:
    get:
      summary: Get document by ID
      security: [{bearerAuth: []}]
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: OK}}
    put:
      summary: Update document by ID (no ownership check — BOLA write)
      security: [{bearerAuth: []}]
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: OK}}
  /api/admin/users:
    get:
      summary: List all users (admin only)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
  /api/internal/config:
    get:
      summary: Internal configuration (should require auth)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
`

// fixtureRolesConfig defines the privilege levels used to pick attacker/victim
// roles. admin is the high-privilege victim; user2 is the low-privilege attacker.
const fixtureRolesConfig = `roles:
  - name: admin
    level: 100
    permissions: ["*:*:all"]
  - name: user1
    level: 50
    permissions: ["read:users:own", "read:profiles:own", "read:orders:own", "read:documents:own"]
  - name: user2
    level: 5
    permissions: ["read:users:own", "read:profiles:own", "read:orders:own", "read:documents:own"]
objects: [users, profiles, orders, documents, admin]
endpoints:
  - {path: "/api/users/{id}", object: users, owner_field: id}
  - {path: "/api/profiles/{id}", object: profiles, owner_field: user_id}
  - {path: "/api/orders/{id}", object: orders, owner_field: user_id}
  - {path: "/api/documents/{id}", object: documents, owner_field: user_id}
`

// fixtureAuthConfig maps each role to its static bearer token.
const fixtureAuthConfig = `method: bearer
roles:
  admin:
    token: "admin-token"
  user1:
    token: "user1-token"
  user2:
    token: "user2-token"
`

// writeFixtureConfigs writes the spec/roles/auth files into a temp dir for the
// given server URL and returns their paths.
func writeFixtureConfigs(t *testing.T, serverURL string) (apiPath, rolesPath, authPath string) {
	t.Helper()
	dir := t.TempDir()

	apiPath = filepath.Join(dir, "api.yaml")
	if err := os.WriteFile(apiPath, []byte(strings.Replace(fixtureSpecTemplate, "%s", serverURL, 1)), 0o644); err != nil {
		t.Fatalf("write api spec: %v", err)
	}
	rolesPath = filepath.Join(dir, "roles.yaml")
	if err := os.WriteFile(rolesPath, []byte(fixtureRolesConfig), 0o644); err != nil {
		t.Fatalf("write roles: %v", err)
	}
	authPath = filepath.Join(dir, "auth.yaml")
	if err := os.WriteFile(authPath, []byte(fixtureAuthConfig), 0o644); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	return apiPath, rolesPath, authPath
}

// restTemplateDir is the path to the production REST templates relative to the
// pkg/runner package directory.
const restTemplateDir = "../../templates/rest"
