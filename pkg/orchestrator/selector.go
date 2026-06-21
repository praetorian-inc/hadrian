package orchestrator

import (
	"regexp"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// MatchesEndpointSelector checks if an operation matches the template's endpoint criteria.
// Evaluates: HasPathParameter, RequiresAuth, Methods, PathPattern, Tags, and the
// parameter-scoped selectors (HasQueryParameter, HasBodyField, QueryParameterNames,
// BodyFieldNames).
// If compiledPathPattern is provided, it is used instead of re-compiling PathPattern each call.
func MatchesEndpointSelector(operation *model.Operation, selector templates.EndpointSelector, compiledPathPattern ...*regexp.Regexp) bool {
	// Check HasPathParameter requirement
	if selector.HasPathParameter {
		if len(operation.PathParams) == 0 {
			return false
		}
	}

	// Check HasQueryParameter requirement
	if selector.HasQueryParameter {
		if len(operation.QueryParams) == 0 {
			return false
		}
	}

	// Check HasBodyField requirement
	if selector.HasBodyField {
		if operation.BodySchema == nil || len(operation.BodySchema.Properties) == 0 {
			return false
		}
	}

	// Check QueryParameterNames: operation must expose at least one query parameter
	// whose name matches one of the listed identity/scope param names.
	if len(selector.QueryParameterNames) > 0 {
		if !operationHasQueryParam(operation, selector.QueryParameterNames) {
			return false
		}
	}

	// Check BodyFieldNames: operation request body must contain at least one of the
	// listed identity/scope field names.
	if len(selector.BodyFieldNames) > 0 {
		if !operationHasBodyField(operation, selector.BodyFieldNames) {
			return false
		}
	}

	// Check RequiresAuth requirement
	if selector.RequiresAuth {
		if !operation.RequiresAuth {
			return false
		}
	}

	// Check Methods (empty list means any method is allowed)
	if len(selector.Methods) > 0 {
		if !containsString(selector.Methods, operation.Method) {
			return false
		}
	}

	// Check PathPattern (optional regex match)
	if selector.PathPattern != "" {
		if len(compiledPathPattern) > 0 && compiledPathPattern[0] != nil {
			if !compiledPathPattern[0].MatchString(operation.Path) {
				return false
			}
		} else {
			matched, err := regexp.MatchString(selector.PathPattern, operation.Path)
			if err != nil || !matched {
				return false
			}
		}
	}

	// Check Tags (intersection required, empty selector tags means any tags match)
	if len(selector.Tags) > 0 {
		if !hasTagIntersection(operation.Tags, selector.Tags) {
			return false
		}
	}

	return true
}

// =============================================================================
// HELPERS
// =============================================================================

// containsString checks if a string is in a slice.
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// operationHasQueryParam returns true if the operation declares a query parameter
// whose name matches (case-insensitively) any of the given names.
func operationHasQueryParam(operation *model.Operation, names []string) bool {
	for _, p := range operation.QueryParams {
		for _, n := range names {
			if strings.EqualFold(p.Name, n) {
				return true
			}
		}
	}
	return false
}

// operationHasBodyField returns true if the operation's request body schema
// declares a property whose name matches (case-insensitively) any of the given names.
func operationHasBodyField(operation *model.Operation, names []string) bool {
	if operation.BodySchema == nil {
		return false
	}
	for field := range operation.BodySchema.Properties {
		for _, n := range names {
			if strings.EqualFold(field, n) {
				return true
			}
		}
	}
	return false
}

// hasTagIntersection returns true if there's any common element between the two slices.
func hasTagIntersection(operationTags, selectorTags []string) bool {
	tagSet := make(map[string]bool)
	for _, tag := range operationTags {
		tagSet[tag] = true
	}

	for _, tag := range selectorTags {
		if tagSet[tag] {
			return true
		}
	}
	return false
}
