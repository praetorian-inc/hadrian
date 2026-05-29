package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// setupTestServer initialises seed data, builds the schema, and returns an
// HTTP handler wired up the same way as main(). Each test gets a fresh
// data set via initData().
func setupTestServer(t *testing.T) http.Handler {
	t.Helper()
	// Provide a throw-away upload dir so uploadPaste tests can write files.
	var err error
	uploadDir, err = os.MkdirTemp("", "vuln-gql-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(uploadDir) })

	initData()
	schema, err := buildSchema()
	if err != nil {
		t.Fatalf("buildSchema: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", makeGraphQLHandler(schema))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`)) //nolint:errcheck
	})
	mux.HandleFunc("/api/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		initData()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"data reset to initial state","pastes":"4","users":"3"}`)) //nolint:errcheck
	})
	return mux
}

// gqlDo sends a GraphQL request and returns the decoded response body map.
func gqlDo(t *testing.T, srv http.Handler, query string, token string) map[string]interface{} {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"query": query})
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return result
}

// loginAndGetToken performs a login mutation and returns the accessToken.
func loginAndGetToken(t *testing.T, srv http.Handler, username, password string) string {
	t.Helper()
	q := `mutation { login(username: "` + username + `", password: "` + password + `") { accessToken } }`
	resp := gqlDo(t, srv, q, "")
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("no data in login response: %v", resp)
	}
	login, ok := data["login"].(map[string]interface{})
	if !ok {
		t.Fatalf("no login in response: %v", data)
	}
	tok, _ := login["accessToken"].(string)
	if tok == "" {
		t.Fatalf("empty accessToken, response: %v", resp)
	}
	return tok
}

// TestLoginReturnsJWT verifies that the login mutation returns a non-empty JWT.
func TestLoginReturnsJWT(t *testing.T) {
	srv := setupTestServer(t)
	tok := loginAndGetToken(t, srv, "admin", "admin123")
	// JWTs are three dot-separated base64 segments
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Errorf("expected JWT with 3 parts, got %d: %s", len(parts), tok)
	}
}

// TestLoginInvalidCredentials verifies that bad credentials return an error.
func TestLoginInvalidCredentials(t *testing.T) {
	srv := setupTestServer(t)
	q := `mutation { login(username: "admin", password: "wrong") { accessToken } }`
	resp := gqlDo(t, srv, q, "")
	if resp["errors"] == nil {
		t.Errorf("expected errors for invalid login, got: %v", resp)
	}
}

// TestPasteByIDReachableBOLA verifies paste(id:1) returns data regardless of
// the calling user — this is the BOLA behaviour under test.
func TestPasteByIDReachableBOLA(t *testing.T) {
	srv := setupTestServer(t)
	// user2 owns paste 2 but can retrieve paste 1 (owned by user1) — BOLA
	tok := loginAndGetToken(t, srv, "user2", "user2pass")
	resp := gqlDo(t, srv, `{ paste(id: 1) { id title ownerId } }`, tok)
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("no data: %v", resp)
	}
	paste, ok := data["paste"].(map[string]interface{})
	if !ok || paste == nil {
		t.Fatalf("paste(id:1) returned nil for user2 — BOLA check failed: %v", data)
	}
	if paste["ownerId"] == nil {
		t.Errorf("ownerId should be present, got: %v", paste)
	}
}

// TestUsersExposesPassword verifies that the users query returns the password
// field in plain text — intentional sensitive-data exposure.
func TestUsersExposesPassword(t *testing.T) {
	srv := setupTestServer(t)
	resp := gqlDo(t, srv, `{ users(id: 1) { id username password } }`, "")
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("no data: %v", resp)
	}
	userList, ok := data["users"].([]interface{})
	if !ok || len(userList) == 0 {
		t.Fatalf("expected at least one user: %v", data)
	}
	u, ok := userList[0].(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected user type: %T", userList[0])
	}
	password, _ := u["password"].(string)
	if password == "" {
		t.Errorf("expected non-empty password field, got empty")
	}
}

// TestSystemDiagnosticsCommandExecution verifies that systemDiagnostics(cmd:"id")
// performs real command execution and returns uid=.
func TestSystemDiagnosticsCommandExecution(t *testing.T) {
	srv := setupTestServer(t)
	resp := gqlDo(t, srv, `{ systemDiagnostics(username:"admin", password:"admin", cmd:"id") }`, "")
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("no data: %v", resp)
	}
	output, _ := data["systemDiagnostics"].(string)
	if !strings.Contains(output, "uid=") {
		t.Errorf("expected 'uid=' in systemDiagnostics output, got: %q", output)
	}
}

// TestIntrospectionEnabled verifies that introspection queries return schema data.
func TestIntrospectionEnabled(t *testing.T) {
	srv := setupTestServer(t)
	resp := gqlDo(t, srv, `{ __schema { queryType { name } } }`, "")
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("no data: %v", resp)
	}
	schema, ok := data["__schema"].(map[string]interface{})
	if !ok {
		t.Fatalf("introspection __schema missing: %v", data)
	}
	qt, _ := schema["queryType"].(map[string]interface{})
	if qt["name"] != "Query" {
		t.Errorf("expected queryType.name=Query, got: %v", qt["name"])
	}
}

// TestHealthEndpoint verifies the /health endpoint returns {"status":"healthy"}.
func TestHealthEndpoint(t *testing.T) {
	srv := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("health: expected 200, got %d", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if body["status"] != "healthy" {
		t.Errorf("expected status=healthy, got: %v", body)
	}
}

// TestUploadPastePathTraversal verifies that uploadPaste writes a file via
// path traversal — intentional vulnerability.
func TestUploadPastePathTraversal(t *testing.T) {
	srv := setupTestServer(t)
	q := `mutation { uploadPaste(content: "pwned", filename: "../../../tmp/traversal-test.txt") { result filename } }`
	resp := gqlDo(t, srv, q, "")
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("no data: %v", resp)
	}
	up, ok := data["uploadPaste"].(map[string]interface{})
	if !ok {
		t.Fatalf("uploadPaste missing: %v", data)
	}
	if up["result"] != "success" {
		t.Errorf("expected result=success, got: %v", up["result"])
	}
	// The resolved filename should be absolute (path traversal escaped upload dir)
	filename, _ := up["filename"].(string)
	if filename == "" {
		t.Errorf("expected non-empty filename in response")
	}
}

// TestResetEndpoint verifies POST /api/reset restores seed data.
func TestResetEndpoint(t *testing.T) {
	srv := setupTestServer(t)
	// Delete a paste to mutate state
	tok := loginAndGetToken(t, srv, "user1", "user1pass")
	gqlDo(t, srv, `mutation { deletePaste(id: 1) { result } }`, tok)

	// Reset
	req := httptest.NewRequest(http.MethodPost, "/api/reset", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("reset: expected 200, got %d", w.Code)
	}

	// paste 1 should be back
	resp := gqlDo(t, srv, `{ paste(id: 1) { id } }`, tok)
	data := resp["data"].(map[string]interface{})
	if data["paste"] == nil {
		t.Errorf("paste 1 should exist after reset, got nil")
	}
}

// TestDeletePasteBOLA verifies that attacker (user2) can delete paste owned by
// victim (user1) — the core BOLA deletion vulnerability.
func TestDeletePasteBOLA(t *testing.T) {
	srv := setupTestServer(t)
	// user2 is attacker; paste 1 is owned by user1 (victim)
	attackerToken := loginAndGetToken(t, srv, "user2", "user2pass")
	resp := gqlDo(t, srv, `mutation { deletePaste(id: 1) { result } }`, attackerToken)
	data := resp["data"].(map[string]interface{})
	del := data["deletePaste"].(map[string]interface{})
	if del["result"] != true {
		t.Errorf("BOLA deletePaste should succeed, got: %v", del)
	}

	// Paste 1 should be gone
	resp2 := gqlDo(t, srv, `{ paste(id: 1) { id } }`, attackerToken)
	data2 := resp2["data"].(map[string]interface{})
	if data2["paste"] != nil {
		t.Errorf("paste 1 should be nil after deletion, got: %v", data2["paste"])
	}
}

// TestCreatePasteStoresPaste guards the contextKey regression: createPaste
// reads user_agent/remote_addr from the request context, which the handler
// stores under the typed contextKey. A type mismatch there made createPaste
// silently fail (graphql-go recovers the resolver panic into a field error).
// This verifies the mutation succeeds and the paste is actually persisted.
func TestCreatePasteStoresPaste(t *testing.T) {
	srv := setupTestServer(t)
	token := loginAndGetToken(t, srv, "user1", "user1pass")
	resp := gqlDo(t, srv, `mutation { createPaste(title: "hello", content: "world", public: true) { paste { id title } } }`, token)
	if resp["errors"] != nil {
		t.Fatalf("createPaste returned errors (contextKey regression?): %v", resp["errors"])
	}
	data := resp["data"].(map[string]interface{})
	cp, ok := data["createPaste"].(map[string]interface{})
	if !ok || cp["paste"] == nil {
		t.Fatalf("createPaste did not return a paste: %v", data)
	}
	paste := cp["paste"].(map[string]interface{})
	newID := paste["id"]
	if newID == nil || paste["title"] != "hello" {
		t.Fatalf("unexpected createPaste result: %v", paste)
	}
	// The paste must actually be retrievable (i.e. it was stored, not dropped).
	resp2 := gqlDo(t, srv, `{ paste(id: 5) { id title } }`, token)
	data2 := resp2["data"].(map[string]interface{})
	if data2["paste"] == nil {
		t.Errorf("newly created paste (id 5) should be retrievable, got nil: %v", resp2)
	}
}

// TestPromoteUserBFLA verifies that a low-privilege attacker (user2) can invoke
// the admin-only promoteUser mutation to escalate a role — the BFLA vector.
func TestPromoteUserBFLA(t *testing.T) {
	srv := setupTestServer(t)
	attackerToken := loginAndGetToken(t, srv, "user2", "user2pass")
	resp := gqlDo(t, srv, `mutation { promoteUser(username: "user2", role: "admin") { id username } }`, attackerToken)
	if resp["errors"] != nil {
		t.Fatalf("promoteUser returned errors: %v", resp["errors"])
	}
	data := resp["data"].(map[string]interface{})
	pu, ok := data["promoteUser"].(map[string]interface{})
	if !ok || pu["username"] != "user2" {
		t.Fatalf("BFLA promoteUser should succeed for a non-admin caller, got: %v", data)
	}
}
