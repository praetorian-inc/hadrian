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
