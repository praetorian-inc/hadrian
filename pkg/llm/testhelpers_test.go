package llm

import (
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
)

// testTriageRequest returns a minimal TriageRequest for testing.
func testTriageRequest() *TriageRequest {
	return &TriageRequest{
		Finding: &model.Finding{
			Category: "API1", Method: "GET", Endpoint: "/api/test",
			Evidence: model.Evidence{Response: model.HTTPResponse{StatusCode: 200, Body: "test"}},
		},
		AttackerRole: &roles.Role{Name: "user", Permissions: []roles.Permission{{Raw: "read:users:own"}}},
		VictimRole:   &roles.Role{Name: "admin", Permissions: []roles.Permission{{Raw: "*:*:*"}}},
	}
}
