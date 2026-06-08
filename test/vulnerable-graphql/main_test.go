//go:build integration
// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// setupTestServer initialises seed data, builds the schema, and returns an
// HTTP handler wired up the same way as main(). Each test gets a fresh
// data set via initData().
func setupTestServer(t *testing.T) http.Handler {
	t.Helper()
	// Root uploadDir under a per-test temp dir (auto-cleaned by t.TempDir).
	// The path-traversal test escapes uploadDir with ".." and lands in this
	// owned parent, so the test never writes to a fixed shared path (which
	// would collide with concurrent runs or pre-existing /tmp state — the
	// cause of a non-hermetic failure under `go test -race ./...`).
	uploadDir = filepath.Join(t.TempDir(), "uploads")
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		t.Fatalf("mkdir uploadDir: %v", err)
	}

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
// It also asserts that the returned paste's ownerId differs from the calling
// user's id, proving cross-user access (not just that data returned).
func TestPasteByIDReachableBOLA(t *testing.T) {
	srv := setupTestServer(t)
	// user2 (id=3) reads paste 1, which is owned by user1 (id=2) — BOLA
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
	// ownerId should be user1's id (2), not user2's id (3)
	ownerID, _ := paste["ownerId"].(float64)
	const user2ID = 3
	if int(ownerID) == user2ID {
		t.Errorf("BOLA check failed: paste ownerId=%v matches calling user id=%d (should be a different user)", ownerID, user2ID)
	}
	if int(ownerID) == 0 {
		t.Errorf("ownerId should be non-zero, got: %v", paste)
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
// It asserts the resolved path actually escaped the upload base dir and
// registers a cleanup to remove the traversed file.
func TestUploadPastePathTraversal(t *testing.T) {
	srv := setupTestServer(t)
	// Escape the uploads dir with "..". With uploadDir = <tmp>/uploads this
	// resolves to <tmp>/traversal-test.txt — outside uploadDir (proving the
	// traversal) but still inside the per-test temp dir, so the write always
	// succeeds and leaves no artifact outside t.TempDir's auto-cleanup.
	q := `mutation { uploadPaste(content: "pwned", filename: "../traversal-test.txt") { result filename } }`
	resp := gqlDo(t, srv, q, "")
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("no data: %v", resp)
	}
	up, ok := data["uploadPaste"].(map[string]interface{})
	if !ok {
		t.Fatalf("uploadPaste missing: %v (errors: %v)", data, resp["errors"])
	}
	if up["result"] != "success" {
		t.Errorf("expected result=success, got: %v", up["result"])
	}
	filename, _ := up["filename"].(string)
	if filename == "" {
		t.Errorf("expected non-empty filename in response")
	}
	// Prove the written path actually escaped the uploads directory.
	// filepath.Join collapses ".." so the resolved path is not under uploadDir.
	if strings.HasPrefix(filename, uploadDir) {
		t.Errorf("path traversal did not escape upload dir: resolved %q is still under %q", filename, uploadDir)
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
	if paste["id"] == nil || paste["title"] != "hello" {
		t.Fatalf("unexpected createPaste result: %v", paste)
	}
	// The paste must actually be retrievable by its returned id (i.e. it was
	// stored, not dropped). Use the id from the response rather than a literal
	// so the test does not couple to the seed-paste count. graphql.ID
	// serialises as a string/number, so format it generically.
	newID := fmt.Sprintf("%v", paste["id"])
	resp2 := gqlDo(t, srv, fmt.Sprintf(`{ paste(id: %s) { id title } }`, newID), token)
	data2 := resp2["data"].(map[string]interface{})
	if data2["paste"] == nil {
		t.Errorf("newly created paste (id %s) should be retrievable, got nil: %v", newID, resp2)
	}
}

// TestEditPasteBOLA verifies that attacker (user2) can edit a paste owned by
// victim (user1) — the core BOLA edit vulnerability. It confirms the edit
// persists when re-read as the victim.
func TestEditPasteBOLA(t *testing.T) {
	srv := setupTestServer(t)
	// user2 is attacker; paste 3 is owned by user1 (victim) — distinct from paste 1 used by delete test
	attackerToken := loginAndGetToken(t, srv, "user2", "user2pass")
	victimToken := loginAndGetToken(t, srv, "user1", "user1pass")

	// Attacker edits victim's paste 3
	editResp := gqlDo(t, srv, `mutation { editPaste(id: 3, title: "BOLA_EDIT", content: "attacker modified") { paste { id title ownerId } } }`, attackerToken)
	if editResp["errors"] != nil {
		t.Fatalf("editPaste returned errors: %v", editResp["errors"])
	}
	editData := editResp["data"].(map[string]interface{})
	ep, ok := editData["editPaste"].(map[string]interface{})
	if !ok || ep["paste"] == nil {
		t.Fatalf("editPaste did not return paste: %v", editData)
	}

	// Victim re-reads paste 3 — change must persist
	verifyResp := gqlDo(t, srv, `{ paste(id: 3) { id title ownerId } }`, victimToken)
	verifyData := verifyResp["data"].(map[string]interface{})
	paste, ok := verifyData["paste"].(map[string]interface{})
	if !ok || paste == nil {
		t.Fatalf("paste(id:3) not found after edit: %v", verifyData)
	}
	if paste["title"] != "BOLA_EDIT" {
		t.Errorf("BOLA edit did not persist: expected title=BOLA_EDIT, got %v", paste["title"])
	}
	// Confirm cross-user: paste owner is user1 (id=2), not attacker user2 (id=3)
	ownerID, _ := paste["ownerId"].(float64)
	const user2ID = 3
	if int(ownerID) == user2ID {
		t.Errorf("ownerId should be victim's (user1=2), not attacker's (user2=3), got %v", ownerID)
	}
}

// TestDeleteAllPastesBFLA verifies that a low-privilege user (user2) can call
// deleteAllPastes — the BFLA vector for bulk deletion without authorisation.
func TestDeleteAllPastesBFLA(t *testing.T) {
	srv := setupTestServer(t)
	attackerToken := loginAndGetToken(t, srv, "user2", "user2pass")

	// Low-privilege user calls the admin-only deleteAllPastes
	resp := gqlDo(t, srv, `{ deleteAllPastes }`, attackerToken)
	if resp["errors"] != nil {
		t.Fatalf("deleteAllPastes returned errors: %v", resp["errors"])
	}
	data := resp["data"].(map[string]interface{})
	if data["deleteAllPastes"] != true {
		t.Errorf("BFLA deleteAllPastes should return true, got: %v", data["deleteAllPastes"])
	}

	// All pastes must be gone
	listResp := gqlDo(t, srv, `{ pastes { id } }`, attackerToken)
	listData := listResp["data"].(map[string]interface{})
	pasteList, _ := listData["pastes"].([]interface{})
	if len(pasteList) != 0 {
		t.Errorf("expected empty pastes after deleteAllPastes, got %d entries", len(pasteList))
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

// TestConcurrentGraphQLAccess exercises the mutex-guarded in-memory store from
// multiple goroutines simultaneously (paste reads, createPaste writes, and a
// reset via /api/reset). Run with -race to verify there are no data races on
// the global pastes/users slices. The helper is goroutine-safe (no t.Fatalf
// off the main goroutine).
func TestConcurrentGraphQLAccess(t *testing.T) {
	srv := setupTestServer(t)
	tok := loginAndGetToken(t, srv, "user2", "user2pass")

	post := func(query string) {
		body, _ := json.Marshal(map[string]string{"query": query})
		req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		srv.ServeHTTP(httptest.NewRecorder(), req)
	}

	const goroutines = 12
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			switch i % 3 {
			case 0:
				post(`{ paste(id: 1) { id ownerId } }`)
			case 1:
				post(`mutation { createPaste(title: "c", content: "x", public: true) { paste { id } } }`)
			default:
				rr := httptest.NewRecorder()
				srv.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/reset", nil))
			}
		}()
	}
	wg.Wait()
}

// TestMeReturnsAuthenticatedUser covers the `me` resolver happy path: the
// logged-in identity is reflected back from the bearer token.
func TestMeReturnsAuthenticatedUser(t *testing.T) {
	srv := setupTestServer(t)
	token := loginAndGetToken(t, srv, "user1", "user1pass")
	resp := gqlDo(t, srv, `{ me { id username } }`, token)
	data := resp["data"].(map[string]interface{})
	me, ok := data["me"].(map[string]interface{})
	if !ok || me == nil {
		t.Fatalf("me resolver returned nil: %v", resp)
	}
	if me["username"] != "user1" {
		t.Errorf("me.username = %v, want user1", me["username"])
	}
}

// TestPastesListReturnsSeedPastes covers the `pastes` list resolver happy path:
// the seed pastes are returned.
func TestPastesListReturnsSeedPastes(t *testing.T) {
	srv := setupTestServer(t)
	token := loginAndGetToken(t, srv, "user1", "user1pass")
	resp := gqlDo(t, srv, `{ pastes { id title } }`, token)
	data := resp["data"].(map[string]interface{})
	list, ok := data["pastes"].([]interface{})
	if !ok || len(list) == 0 {
		t.Fatalf("pastes resolver returned no pastes: %v", resp)
	}
}

// TestCreateUserMutation covers the `createUser` mutation happy path: a new
// account is created and echoed back.
func TestCreateUserMutation(t *testing.T) {
	srv := setupTestServer(t)
	token := loginAndGetToken(t, srv, "user1", "user1pass")
	resp := gqlDo(t, srv, `mutation { createUser(userData: {username: "newbie", email: "n@example.com", password: "pw"}) { user { id username } } }`, token)
	if resp["errors"] != nil {
		t.Fatalf("createUser returned errors: %v", resp["errors"])
	}
	data := resp["data"].(map[string]interface{})
	cu := data["createUser"].(map[string]interface{})
	user, ok := cu["user"].(map[string]interface{})
	if !ok || user["username"] != "newbie" {
		t.Fatalf("unexpected createUser result: %v", data)
	}
}

// TestUsernameCapitalize covers the username(capitalize:true) field branch and
// its empty-username guard (regression: an empty username must not panic the
// resolver). It creates a user with an empty username, then reads it back with
// capitalize:true via the users list.
func TestUsernameCapitalize(t *testing.T) {
	srv := setupTestServer(t)
	token := loginAndGetToken(t, srv, "user1", "user1pass")

	// Normal username is capitalized.
	resp := gqlDo(t, srv, `{ me { username(capitalize: true) } }`, token)
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("me query returned no data: %v", resp)
	}
	me, ok := data["me"].(map[string]interface{})
	if !ok {
		t.Fatalf("me query returned no me object: %v", resp)
	}
	if me["username"] != "User1" {
		t.Errorf("capitalize: got %v, want User1", me["username"])
	}

	// Empty username must not panic (returns ""), proving the len-guard holds.
	if r := gqlDo(t, srv, `mutation { createUser(userData: {username: "", email: "e@example.com", password: "pw"}) { user { id } } }`, token); r["errors"] != nil {
		t.Fatalf("createUser with empty username errored: %v", r["errors"])
	}
	resp2 := gqlDo(t, srv, `{ users { username(capitalize: true) } }`, token)
	if resp2["errors"] != nil {
		t.Fatalf("username(capitalize) panicked/errored on empty username: %v", resp2["errors"])
	}
}

// TestSystemDebugInfoDisclosure covers the systemDebug resolver (intentional
// information disclosure) happy path.
func TestSystemDebugInfoDisclosure(t *testing.T) {
	srv := setupTestServer(t)
	token := loginAndGetToken(t, srv, "user1", "user1pass")
	resp := gqlDo(t, srv, `{ systemDebug(arg: "x") }`, token)
	data := resp["data"].(map[string]interface{})
	if s, _ := data["systemDebug"].(string); !strings.Contains(s, "DEBUG:") {
		t.Errorf("systemDebug = %q, want a DEBUG string", s)
	}
}
