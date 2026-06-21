package orchestrator

import (
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
)

// Parameter-scoped BOLA selectors: HasQueryParameter, HasBodyField,
// QueryParameterNames, BodyFieldNames.
func TestMatchesEndpointSelector_ParameterScoped(t *testing.T) {
	searchOp := &model.Operation{
		Method:       "GET",
		Path:         "/lists/search",
		RequiresAuth: true,
		QueryParams: []model.Parameter{
			{Name: "filter[user-ids]", In: "query"},
			{Name: "limit", In: "query"},
		},
	}
	bodyOp := &model.Operation{
		Method:       "POST",
		Path:         "/api/v5/fetchRequestHistory",
		RequiresAuth: true,
		BodySchema: &model.Schema{
			Type: "object",
			Properties: map[string]*model.SchemaProperty{
				"username": {},
				"page":     {},
			},
		},
	}
	noParamOp := &model.Operation{
		Method:       "GET",
		Path:         "/health",
		RequiresAuth: false,
	}

	t.Run("HasQueryParameter matches an op with query params", func(t *testing.T) {
		assert.True(t, MatchesEndpointSelector(searchOp, templates.EndpointSelector{HasQueryParameter: true}))
		assert.False(t, MatchesEndpointSelector(noParamOp, templates.EndpointSelector{HasQueryParameter: true}))
	})

	t.Run("HasBodyField matches an op with a request body", func(t *testing.T) {
		assert.True(t, MatchesEndpointSelector(bodyOp, templates.EndpointSelector{HasBodyField: true}))
		assert.False(t, MatchesEndpointSelector(searchOp, templates.EndpointSelector{HasBodyField: true}))
	})

	t.Run("QueryParameterNames matches by name, case-insensitively", func(t *testing.T) {
		assert.True(t, MatchesEndpointSelector(searchOp, templates.EndpointSelector{
			QueryParameterNames: []string{"FILTER[USER-IDS]"},
		}))
		assert.False(t, MatchesEndpointSelector(searchOp, templates.EndpointSelector{
			QueryParameterNames: []string{"account_id"},
		}))
		// op with no query params never matches a name requirement
		assert.False(t, MatchesEndpointSelector(noParamOp, templates.EndpointSelector{
			QueryParameterNames: []string{"user_id"},
		}))
	})

	t.Run("BodyFieldNames matches by field name, case-insensitively", func(t *testing.T) {
		assert.True(t, MatchesEndpointSelector(bodyOp, templates.EndpointSelector{
			BodyFieldNames: []string{"Username"},
		}))
		assert.False(t, MatchesEndpointSelector(bodyOp, templates.EndpointSelector{
			BodyFieldNames: []string{"email"},
		}))
		// op with no body never matches a body-field requirement
		assert.False(t, MatchesEndpointSelector(searchOp, templates.EndpointSelector{
			BodyFieldNames: []string{"username"},
		}))
	})

	t.Run("HasBodyField is false when BodySchema is non-nil but Properties is empty", func(t *testing.T) {
		emptyBodyOp := &model.Operation{
			Method:       "POST",
			Path:         "/api/v5/empty",
			RequiresAuth: true,
			BodySchema: &model.Schema{
				Type:       "object",
				Properties: map[string]*model.SchemaProperty{},
			},
		}
		assert.False(t, MatchesEndpointSelector(emptyBodyOp, templates.EndpointSelector{HasBodyField: true}))
		assert.False(t, MatchesEndpointSelector(emptyBodyOp, templates.EndpointSelector{BodyFieldNames: []string{"username"}}))
	})

	t.Run("new selectors compose with existing ones (AND semantics)", func(t *testing.T) {
		sel := templates.EndpointSelector{
			RequiresAuth:   true,
			Methods:        []string{"POST"},
			BodyFieldNames: []string{"username"},
		}
		assert.True(t, MatchesEndpointSelector(bodyOp, sel))
		// wrong method → no match even though the body field is present
		assert.False(t, MatchesEndpointSelector(searchOp, sel))
	})
}
