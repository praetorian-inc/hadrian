//go:build integration

package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// webCacheDeceptionHandler: 6 GET endpoints modelling a CDN in front of an authed API.
//
//	/api/account/statement — POSITIVE #1: unauth GET -> 200 + sensitive body + CF-Cache-Status: HIT. MUST flag.
//	/api/account/invoice   — POSITIVE #2: unauth GET -> 200 + sensitive body + X-Cache: TCP_HIT (Akamai). MUST flag.
//	/api/account/settings  — NEG #1 (anti-dup vs API2): 200 unauth, NO cache header. MUST NOT flag.
//	/api/account/secure    — NEG #2: 401 unauth (properly protected). MUST NOT flag.
//	/api/account/history   — NEG #3 (regression): 200 unauth + sensitive body + bare `Age` header only
//	                          (no CF-Cache-Status/X-Cache). Proves the removed Age matcher arm no longer
//	                          fires — a bare positive Age fires on any cached response.
//	/api/account/profile   — NEG #4 (regression): 200 unauth + sensitive body + Imperva-style `X-Iinfo`
//	                          header only (no CF-Cache-Status/X-Cache). Proves the removed X-Iinfo matcher
//	                          arm no longer fires — Imperva sends X-Iinfo on origin/miss responses too.
func webCacheDeceptionHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/account/statement", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("CF-Cache-Status", "HIT")
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"account_id": 1, "holder": "Victim User", "balance": 10425.50,
			"iban": "DE89370400440532013000", "statement_pdf": "confidential",
		})
	})
	mux.HandleFunc("/api/account/invoice", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Cache", "TCP_HIT from edge.akamai.example")
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"account_id": 1, "holder": "Victim User", "invoice_total": 4821.00,
			"billing_address": "123 Confidential Ln", "invoice_pdf": "confidential",
		})
	})
	mux.HandleFunc("/api/account/settings", func(w http.ResponseWriter, _ *http.Request) {
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"account_id": 1, "email": "victim@example.com", "twofa_enabled": false,
		})
	})
	mux.HandleFunc("/api/account/secure", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := fixtureUser(r); !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		fixtureJSON(w, http.StatusOK, map[string]interface{}{"account_id": 1, "secret": "value"})
	})
	mux.HandleFunc("/api/account/history", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Age", "120")
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"account_id": 1, "holder": "Victim User", "transactions": []string{"txn-1", "txn-2"},
		})
	})
	mux.HandleFunc("/api/account/profile", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Iinfo", "1-12345678-12345678 2NNN RT(1694300000000 1) q(0 0 0 -1) r(0 0) U6")
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"account_id": 1, "holder": "Victim User", "ssn": "123-45-6789",
		})
	})
	return mux
}

const webCacheDeceptionSpec = `openapi: "3.0.0"
info:
  title: Web Cache Deception Test API
  version: "1.0.0"
servers:
  - url: "%s"
paths:
  /api/account/statement:
    get:
      summary: Account statement (cacheable authenticated response)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
  /api/account/invoice:
    get:
      summary: Account invoice (cacheable authenticated response, Akamai X-Cache)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
  /api/account/settings:
    get:
      summary: Account settings (broken auth, not cache-served)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
  /api/account/secure:
    get:
      summary: Account secure resource (properly protected)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
  /api/account/history:
    get:
      summary: Account history (bare Age header only, no cache-HIT status)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
  /api/account/profile:
    get:
      summary: Account profile (Imperva X-Iinfo header only, no cache-HIT status)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
`

func runWebCacheDeceptionTemplates(t *testing.T, templateIDs ...string) []*model.Finding {
	t.Helper()
	server := httptest.NewServer(webCacheDeceptionHandler())
	t.Cleanup(server.Close)

	dir := t.TempDir()
	apiPath := filepath.Join(dir, "api.yaml")
	if err := os.WriteFile(apiPath, []byte(strings.Replace(webCacheDeceptionSpec, "%s", server.URL, 1)), 0o644); err != nil {
		t.Fatalf("write api spec: %v", err)
	}
	rolesPath := filepath.Join(dir, "roles.yaml")
	if err := os.WriteFile(rolesPath, []byte(fixtureRolesConfig), 0o644); err != nil {
		t.Fatalf("write roles: %v", err)
	}
	authPath := filepath.Join(dir, "auth.yaml")
	if err := os.WriteFile(authPath, []byte(fixtureAuthConfig), 0o644); err != nil {
		t.Fatalf("write auth: %v", err)
	}

	config := Config{
		API: apiPath, Roles: rolesPath, Auth: authPath,
		TemplateDir: restTemplateDir, Categories: []string{"all"},
		Templates: templateIDs, RateLimit: 50.0, Timeout: 30, Output: "json",
	}
	findings, err := RunTest(context.Background(), config)
	require.NoError(t, err, "RunTest should not error against the WCD fixture")
	return findings
}

func TestIntegration_WebCacheDeception(t *testing.T) {
	findings := runWebCacheDeceptionTemplates(t, "12-api8-web-cache-deception")
	var endpoints []string
	flaggedEndpoints := make(map[string]bool)
	for _, f := range findings {
		endpoints = append(endpoints, f.Method+" "+f.Endpoint)
		flaggedEndpoints[f.Endpoint] = true
	}
	require.Len(t, findings, 2, "WCD template must flag exactly the two CDN-cached endpoints (CF-Cache-Status and X-Cache/Akamai); got %v", endpoints)
	assert.True(t, flaggedEndpoints["/api/account/statement"], "the Cloudflare CF-Cache-Status: HIT endpoint must be flagged; got %v", endpoints)
	assert.True(t, flaggedEndpoints["/api/account/invoice"], "the Akamai X-Cache: TCP_HIT endpoint must be flagged; got %v", endpoints)
	assert.False(t, flaggedEndpoints["/api/account/history"], "a bare Age header (no cache-HIT status) must NOT be flagged — the removed Age matcher arm must not fire; got %v", endpoints)
	assert.False(t, flaggedEndpoints["/api/account/profile"], "an Imperva X-Iinfo header alone (no cache-HIT status) must NOT be flagged — the removed X-Iinfo matcher arm must not fire; got %v", endpoints)
	for _, f := range findings {
		assert.Equal(t, "API8:2023", f.Category, "finding for %s must be categorized as API8:2023", f.Endpoint)
		assert.NotEqual(t, "/api/account/settings", f.Endpoint, "plain broken auth (200, no cache header) must NOT be flagged")
		assert.NotEqual(t, "/api/account/secure", f.Endpoint, "a properly protected endpoint (401) must NOT be flagged")
		assert.NotEqual(t, "/api/account/history", f.Endpoint, "bare Age header (no cache-HIT status) must NOT be flagged")
		assert.NotEqual(t, "/api/account/profile", f.Endpoint, "Imperva X-Iinfo header alone (no cache-HIT status) must NOT be flagged")
	}
}
