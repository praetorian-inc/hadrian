package orchestrator

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/hadrian/pkg/templates"
)

func TestOperationToMethod_PatchAndWrite(t *testing.T) {
	assert.Equal(t, http.MethodPatch, operationToMethod("patch"))
	assert.Equal(t, http.MethodPatch, operationToMethod("write"))
	assert.Equal(t, http.MethodPatch, operationToMethod("PATCH"))
	// Existing behavior unchanged
	assert.Equal(t, http.MethodGet, operationToMethod("read"))
	assert.Equal(t, http.MethodPost, operationToMethod("create"))
	assert.Equal(t, http.MethodPut, operationToMethod("update"))
	assert.Equal(t, http.MethodDelete, operationToMethod("delete"))
}

// Body-field BOLA: the victim's identity captured in setup is substituted into a
// raw request body and replayed by the attacker. Verifies the attack request is
// built with the substituted body, PATCH method (from operation "write"), and a
// default JSON Content-Type.
func TestExecuteMutation_BodyFieldSubstitution(t *testing.T) {
	setupResp := newMockResponse(200, `{"username": "victimUser"}`)
	attackResp := newMockResponse(200, `{"data": "victim request history"}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}

	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "api1-bola-body-field",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:                "/api/v5/userInfo",
					Operation:           "read",
					Auth:                "victim",
					StoreResponseFields: map[string]string{"victim_username": "username"},
				},
			},
			Attack: &templates.Phase{
				Path:           "/api/v5/fetchRequestHistory",
				Operation:      "write", // -> PATCH
				Auth:           "attacker",
				Body:           `{"username":"{victim_username}"}`,
				ExpectedStatus: 200,
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"create",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	assert.Equal(t, http.MethodPatch, attackReq.Method)
	assert.Equal(t, "application/json", attackReq.Header.Get("Content-Type"))

	require.NotNil(t, attackReq.Body)
	bodyBytes, err := io.ReadAll(attackReq.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"username":"victimUser"}`, string(bodyBytes))
}

// Query-param BOLA: the victim's identity captured in setup is substituted into a
// query parameter expressed in the attack phase `path`. This is the primary
// mechanism for filter-style cross-user enumeration (e.g. ?filter[user-ids]=).
func TestExecuteMutation_QueryParamSubstitutionInPath(t *testing.T) {
	setupResp := newMockResponse(200, `{"id": "victim-42"}`)
	attackResp := newMockResponse(200, `{"data": "victim records"}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}

	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "api1-bola-query-param",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:                "/me",
					Operation:           "read",
					Auth:                "victim",
					StoreResponseFields: map[string]string{"victim_id": "id"},
				},
			},
			Attack: &templates.Phase{
				Path:           "/lists/search?filter[user-ids]={victim_id}",
				Operation:      "read",
				Auth:           "attacker",
				ExpectedStatus: 200,
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"read",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	assert.Equal(t, "/lists/search", attackReq.URL.Path)
	assert.Equal(t, "victim-42", attackReq.URL.Query().Get("filter[user-ids]"))
}

// The body's Content-Type must not be clobbered by a global custom header.
func TestExecuteMutation_BodyContentTypeNotClobberedByCustomHeader(t *testing.T) {
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{attackResp}}
	// Global custom header that previously overrode the body Content-Type.
	executor := NewMutationExecutor(client, map[string]string{"Content-Type": "text/plain"})

	tmpl := &templates.Template{
		ID: "ct-precedence",
		TestPhases: &templates.TestPhases{
			Attack: &templates.Phase{
				Path:      "/api/v1/resource",
				Operation: "write",
				Auth:      "attacker",
				Body:      `{"k":"v"}`,
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"write",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 1)
	assert.Equal(t, "application/json", client.requests[0].Header.Get("Content-Type"))
}

// An attack Phase with an explicit ContentType must use that Content-Type rather
// than the default "application/json". Mirrors the structure of
// TestExecuteMutation_BodyContentTypeNotClobberedByCustomHeader.
func TestExecuteMutation_ExplicitContentTypeHonored(t *testing.T) {
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{attackResp}}
	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "explicit-ct",
		TestPhases: &templates.TestPhases{
			Attack: &templates.Phase{
				Path:        "/api/v1/resource",
				Operation:   "write",
				Auth:        "attacker",
				Body:        `{"k":"v"}`,
				ContentType: "application/merge-patch+json",
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"write",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 1)
	assert.Equal(t, "application/merge-patch+json", client.requests[0].Header.Get("Content-Type"))
}

// A typo'd or unknown {alias} in the Body must pass through literally — it must
// not be stripped, errored on, or partially substituted. This pins the documented
// contract from buildRequestBody's comment.
func TestExecuteMutation_UnresolvedBodyAliasSentLiterally(t *testing.T) {
	setupResp := newMockResponse(200, `{"id":"victim-1"}`)
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}
	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "unresolved-alias",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:                "/api/v5/userInfo",
					Operation:           "read",
					Auth:                "victim",
					StoreResponseFields: map[string]string{"victim_id": "id"},
				},
			},
			Attack: &templates.Phase{
				Path:      "/api/v5/fetchRequestHistory",
				Operation: "write",
				Auth:      "attacker",
				Body:      `{"u":"{not_a_real_alias}"}`,
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"write",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	require.NotNil(t, attackReq.Body)
	bodyBytes, err := io.ReadAll(attackReq.Body)
	require.NoError(t, err)
	assert.Contains(t, string(bodyBytes), "{not_a_real_alias}")
}

// A stored value that contains a double-quote must be JSON-escaped when substituted
// into a JSON body, so the outgoing body stays valid JSON. Pins the security fix in
// buildRequestBody / jsonStringEscape.
func TestExecuteMutation_BodyValueJSONEscaped(t *testing.T) {
	// The stored username contains a literal double-quote: ev"il
	setupResp := newMockResponse(200, `{"username":"ev\"il"}`)
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}
	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "json-escape-body",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:                "/api/v5/userInfo",
					Operation:           "read",
					Auth:                "victim",
					StoreResponseFields: map[string]string{"victim_username": "username"},
				},
			},
			Attack: &templates.Phase{
				Path:      "/api/v5/fetchRequestHistory",
				Operation: "write",
				Auth:      "attacker",
				Body:      `{"username":"{victim_username}"}`,
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"write",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	require.NotNil(t, attackReq.Body)
	bodyBytes, err := io.ReadAll(attackReq.Body)
	require.NoError(t, err)

	// The outgoing body must be valid JSON and round-trip to the original value
	// including the embedded double-quote character.
	assert.JSONEq(t, `{"username":"ev\"il"}`, string(bodyBytes))
}

// TestExecuteMutation_QueryParamValueEscaped pins the security fix: a stored value
// substituted into a query-string {alias} is URL-query-escaped, so query-significant
// characters in an attacker-controlled stored value cannot break out of the parameter
// value and inject extra query parameters or alter existing ones.
func TestExecuteMutation_QueryParamValueEscaped(t *testing.T) {
	// The stored value contains a space, an ampersand, and an '=' that, if substituted
	// raw, would inject a second query parameter (injected=1) and corrupt 'owner'.
	setupResp := newMockResponse(200, `{"id":"a b&injected=1"}`)
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}

	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "query-param-value-escaped",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:                "/me",
					Operation:           "read",
					Auth:                "victim",
					StoreResponseFields: map[string]string{"victim_id": "id"},
				},
			},
			Attack: &templates.Phase{
				Path:           "/x?owner={victim_id}",
				Operation:      "read",
				Auth:           "attacker",
				ExpectedStatus: 200,
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"read",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	// The full stored value round-trips intact inside 'owner' (query-unescaped).
	assert.Equal(t, "a b&injected=1", attackReq.URL.Query().Get("owner"))
	// No extra parameter was injected by the embedded '&injected=1'.
	assert.Equal(t, "", attackReq.URL.Query().Get("injected"))
}

// TestExecuteMutation_PathSegmentValueEscaped pins the security fix for path-segment
// substitution: a stored value containing '/' or '?' is URL-path-escaped, so it stays
// a single path segment and cannot inject extra segments or a query string.
func TestExecuteMutation_PathSegmentValueEscaped(t *testing.T) {
	// The stored value contains '/' and '?' — raw substitution would alter the path
	// structure and start a query string.
	setupResp := newMockResponse(200, `{"id":"a/b?c"}`)
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}

	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "path-segment-value-escaped",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:                "/me",
					Operation:           "read",
					Auth:                "victim",
					StoreResponseFields: map[string]string{"id": "id"},
				},
			},
			Attack: &templates.Phase{
				Path:           "/users/{id}",
				Operation:      "read",
				Auth:           "attacker",
				ExpectedStatus: 200,
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"read",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	// No query string was injected by the embedded '?'.
	assert.Equal(t, "", attackReq.URL.RawQuery)
	// The path decodes back to a single "/users/a/b?c" segment value: EscapedPath
	// retains the percent-encoding, while Path (decoded) shows the original value.
	assert.Equal(t, "/users/a%2Fb%3Fc", attackReq.URL.EscapedPath())
	assert.Equal(t, "/users/a/b?c", attackReq.URL.Path)
}

// TestExecuteMutation_FormBodyValueEscaped pins the security fix for
// application/x-www-form-urlencoded bodies: a stored value is URL-query-escaped, so an
// attacker-controlled value cannot inject extra form fields.
func TestExecuteMutation_FormBodyValueEscaped(t *testing.T) {
	// The stored value contains '&' and '=' that, if substituted raw, would inject an
	// 'admin=true' form field.
	setupResp := newMockResponse(200, `{"id":"x&admin=true"}`)
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}

	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "form-body-value-escaped",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:                "/me",
					Operation:           "read",
					Auth:                "victim",
					StoreResponseFields: map[string]string{"victim_id": "id"},
				},
			},
			Attack: &templates.Phase{
				Path:        "/api/v1/resource",
				Operation:   "write",
				Auth:        "attacker",
				Body:        "field={victim_id}",
				ContentType: "application/x-www-form-urlencoded",
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"write",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	require.NotNil(t, attackReq.Body)
	bodyBytes, err := io.ReadAll(attackReq.Body)
	require.NoError(t, err)
	// The value is query-escaped: '&' -> %26, '=' -> %3D. No 'admin' field injected.
	assert.Equal(t, "field=x%26admin%3Dtrue", string(bodyBytes))
}

// TestExecuteMutation_NonJSONBodyValueRaw pins the identityEscape default branch of
// buildRequestBody: a content type that is neither JSON, form, nor XML (text/plain)
// receives the substituted stored value VERBATIM (no escaping).
func TestExecuteMutation_NonJSONBodyValueRaw(t *testing.T) {
	setupResp := newMockResponse(200, `{"username":"a\"b&c"}`)
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}
	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "raw-body-passthrough",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{Path: "/api/v5/userInfo", Operation: "read", Auth: "victim",
					StoreResponseFields: map[string]string{"victim_username": "username"}},
			},
			Attack: &templates.Phase{Path: "/api/v5/fetchRequestHistory", Operation: "write", Auth: "attacker",
				Body: "<u>{victim_username}</u>", ContentType: "text/plain"},
		},
	}

	_, err := executor.ExecuteMutation(context.Background(), tmpl, "write",
		"attacker@example.com", "victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"), "http://localhost:8080")
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	require.NotNil(t, attackReq.Body)
	bodyBytes, err := io.ReadAll(attackReq.Body)
	require.NoError(t, err)
	assert.Equal(t, `<u>a"b&c</u>`, string(bodyBytes))
}

// TestExecuteMutation_XMLBodyValueEscaped pins the XML escaper branch: a stored value
// with markup-significant characters is XML-escaped in an application/xml body.
func TestExecuteMutation_XMLBodyValueEscaped(t *testing.T) {
	setupResp := newMockResponse(200, `{"username":"a<b&c"}`)
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}
	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "xml-escape-body",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{Path: "/api/v5/userInfo", Operation: "read", Auth: "victim",
					StoreResponseFields: map[string]string{"victim_username": "username"}},
			},
			Attack: &templates.Phase{Path: "/api/v5/fetchRequestHistory", Operation: "write", Auth: "attacker",
				Body: "<u>{victim_username}</u>", ContentType: "application/xml"},
		},
	}

	_, err := executor.ExecuteMutation(context.Background(), tmpl, "write",
		"attacker@example.com", "victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"), "http://localhost:8080")
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	require.NotNil(t, attackReq.Body)
	bodyBytes, err := io.ReadAll(attackReq.Body)
	require.NoError(t, err)
	assert.Equal(t, `<u>a&lt;b&amp;c</u>`, string(bodyBytes))
}

// TestExecuteMutation_MixedCaseContentTypeStillEscapes pins QUAL-002: HTTP media
// types are case-insensitive (RFC 7231), so a hand-authored mixed-case content_type
// such as "Application/JSON" must still select the JSON escaper rather than falling
// through to raw passthrough. The stored username contains a double-quote that must
// be JSON-string-escaped for the outgoing body to stay valid JSON.
func TestExecuteMutation_MixedCaseContentTypeStillEscapes(t *testing.T) {
	setupResp := newMockResponse(200, `{"username":"ev\"il"}`)
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}
	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "mixed-case-content-type",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{Path: "/api/v5/userInfo", Operation: "read", Auth: "victim",
					StoreResponseFields: map[string]string{"victim_username": "username"}},
			},
			Attack: &templates.Phase{Path: "/api/v5/fetchRequestHistory", Operation: "write", Auth: "attacker",
				Body: `{"username":"{victim_username}"}`, ContentType: "Application/JSON"},
		},
	}

	_, err := executor.ExecuteMutation(context.Background(), tmpl, "write",
		"attacker@example.com", "victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"), "http://localhost:8080")
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	require.NotNil(t, attackReq.Body)
	bodyBytes, err := io.ReadAll(attackReq.Body)
	require.NoError(t, err)
	// Escaping applied despite the non-lowercase content type: body round-trips as valid JSON.
	assert.JSONEq(t, `{"username":"ev\"il"}`, string(bodyBytes))
	// And the wire Content-Type header preserves the author's original casing.
	assert.Equal(t, "Application/JSON", attackReq.Header.Get("Content-Type"))
}

// TestExecuteMutation_NoSecondOrderAliasResubstitution pins the single-pass
// substitution fix: a stored value that literally contains another alias's {token}
// is NOT re-expanded on a later pass. The regex walk is left-to-right in a single
// pass, so substituted text is never re-scanned.
func TestExecuteMutation_NoSecondOrderAliasResubstitution(t *testing.T) {
	// alias_a's stored value is the literal string "{alias_b}".
	// alias_b's stored value is "X".
	// A naive multi-pass substitution would first expand {alias_a} → "{alias_b}",
	// then expand that result → "X". The single-pass contract must prevent this.
	setupResp := newMockResponse(200, `{"a":"{alias_b}","b":"X"}`)
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{setupResp, attackResp}}

	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "no-second-order-resubstitution",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:      "/api/setup",
					Operation: "read",
					Auth:      "victim",
					// alias_a → the literal string "{alias_b}"; alias_b → "X"
					StoreResponseFields: map[string]string{
						"alias_a": "a",
						"alias_b": "b",
					},
				},
			},
			Attack: &templates.Phase{
				Path:      "/api/attack",
				Operation: "write",
				Auth:      "attacker",
				// Both placeholders are in JSON string positions; jsonStringEscape
				// leaves { and } unescaped, so the literal {alias_b} round-trips.
				Body: `{"first":"{alias_a}","second":"{alias_b}"}`,
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"write",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 2)

	attackReq := client.requests[1]
	require.NotNil(t, attackReq.Body)
	bodyBytes, err := io.ReadAll(attackReq.Body)
	require.NoError(t, err)

	// alias_a must expand to the literal string "{alias_b}" (NOT to "X").
	// alias_b must expand to "X".
	// If second-order substitution occurred, "first" would be "X" — the test would fail.
	assert.JSONEq(t, `{"first":"{alias_b}","second":"X"}`, string(bodyBytes))
}

// A phase with no Body must not set a body or Content-Type (regression guard for
// the new body-handling branch).
func TestExecuteMutation_NoBodyLeavesRequestBodyNil(t *testing.T) {
	attackResp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{responses: []*http.Response{attackResp}}
	executor := NewMutationExecutor(client, nil)

	tmpl := &templates.Template{
		ID: "no-body",
		TestPhases: &templates.TestPhases{
			Attack: &templates.Phase{
				Path:      "/api/v1/resource",
				Operation: "read",
				Auth:      "attacker",
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"read",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)
	require.NoError(t, err)
	require.Len(t, client.requests, 1)
	assert.Equal(t, http.MethodGet, client.requests[0].Method)
	assert.Equal(t, "", client.requests[0].Header.Get("Content-Type"))
}
