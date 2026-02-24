package orchestrator

import (
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
)

func TestMatchesEndpointSelector(t *testing.T) {
	t.Run("matches operation with path parameter when required", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "GET",
			Path:         "/api/users/{id}",
			PathParams:   []model.Parameter{{Name: "id", In: "path"}},
			RequiresAuth: true,
			Tags:         []string{"users"},
		}
		selector := templates.EndpointSelector{
			HasPathParameter: true,
			RequiresAuth:     true,
			Methods:          []string{"GET"},
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.True(t, result)
	})

	t.Run("does not match when path parameter missing but required", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "GET",
			Path:         "/api/users",
			PathParams:   []model.Parameter{}, // No path params
			RequiresAuth: true,
		}
		selector := templates.EndpointSelector{
			HasPathParameter: true, // Required
			RequiresAuth:     true,
			Methods:          []string{"GET"},
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.False(t, result, "should not match when path parameter is required but missing")
	})

	t.Run("matches when auth not required by selector", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "GET",
			Path:         "/api/public",
			RequiresAuth: false,
		}
		selector := templates.EndpointSelector{
			HasPathParameter: false,
			RequiresAuth:     false,
			Methods:          []string{"GET"},
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.True(t, result)
	})

	t.Run("does not match when auth required but operation is public", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "GET",
			Path:         "/api/public",
			RequiresAuth: false, // Public endpoint
		}
		selector := templates.EndpointSelector{
			HasPathParameter: false,
			RequiresAuth:     true, // Requires auth
			Methods:          []string{"GET"},
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.False(t, result, "should not match when auth required but endpoint is public")
	})

	t.Run("matches when method is in selector list", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "POST",
			Path:         "/api/users",
			RequiresAuth: true,
		}
		selector := templates.EndpointSelector{
			Methods: []string{"GET", "POST", "PUT"},
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.True(t, result)
	})

	t.Run("does not match when method not in selector list", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "DELETE",
			Path:         "/api/users/{id}",
			RequiresAuth: true,
		}
		selector := templates.EndpointSelector{
			Methods: []string{"GET", "POST"}, // DELETE not included
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.False(t, result, "should not match when method not in list")
	})

	t.Run("matches when methods list is empty (any method)", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "DELETE",
			Path:         "/api/users/{id}",
			RequiresAuth: true,
		}
		selector := templates.EndpointSelector{
			Methods: []string{}, // Empty = any method
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.True(t, result, "empty methods list should match any method")
	})

	t.Run("matches path pattern with regex", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "GET",
			Path:         "/api/users/{id}/profile",
			RequiresAuth: true,
		}
		selector := templates.EndpointSelector{
			PathPattern: `/api/users/.*`,
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.True(t, result)
	})

	t.Run("does not match when path pattern fails", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "GET",
			Path:         "/api/orders/{id}",
			RequiresAuth: true,
		}
		selector := templates.EndpointSelector{
			PathPattern: `/api/users/.*`, // Doesn't match orders
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.False(t, result, "should not match when path pattern doesn't match")
	})

	t.Run("matches when tags intersect", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "GET",
			Path:         "/api/users/{id}",
			RequiresAuth: true,
			Tags:         []string{"users", "authentication"},
		}
		selector := templates.EndpointSelector{
			Tags: []string{"users"},
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.True(t, result)
	})

	t.Run("does not match when tags don't intersect", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "GET",
			Path:         "/api/users/{id}",
			RequiresAuth: true,
			Tags:         []string{"orders"},
		}
		selector := templates.EndpointSelector{
			Tags: []string{"users", "authentication"},
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.False(t, result, "should not match when no tag intersection")
	})

	t.Run("matches when selector tags empty (any tags)", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "GET",
			Path:         "/api/users/{id}",
			RequiresAuth: true,
			Tags:         []string{"orders"},
		}
		selector := templates.EndpointSelector{
			Tags: []string{}, // Empty = any tags
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.True(t, result, "empty tags should match any operation")
	})

	t.Run("complex matching with all criteria", func(t *testing.T) {
		// Arrange
		operation := &model.Operation{
			Method:       "GET",
			Path:         "/api/users/{id}/profile",
			PathParams:   []model.Parameter{{Name: "id", In: "path"}},
			RequiresAuth: true,
			Tags:         []string{"users", "profile"},
		}
		selector := templates.EndpointSelector{
			HasPathParameter: true,
			RequiresAuth:     true,
			Methods:          []string{"GET"},
			PathPattern:      `/api/users/.*`,
			Tags:             []string{"users"},
		}

		// Act
		result := MatchesEndpointSelector(operation, selector)

		// Assert
		assert.True(t, result)
	})
}
