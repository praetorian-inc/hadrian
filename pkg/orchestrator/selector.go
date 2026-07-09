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

	// Check parameter-scoped selectors (query/body identity fields).
	if !MatchesParamScopedSelectors(operation, selector) {
		return false
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

// OperationHasQueryParam returns true if the operation declares a query parameter
// whose name matches (case-insensitively) any of the given names.
func OperationHasQueryParam(operation *model.Operation, names []string) bool {
	for _, p := range operation.QueryParams {
		for _, n := range names {
			if strings.EqualFold(p.Name, n) {
				return true
			}
		}
	}
	return false
}

// OperationHasBodyField returns true if the operation's request body schema
// declares a property whose name matches (case-insensitively) any of the given names.
func OperationHasBodyField(operation *model.Operation, names []string) bool {
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

// MatchesParamScopedSelectors reports whether an operation satisfies the
// parameter-scoped endpoint_selector fields: HasQueryParameter, HasBodyField,
// QueryParameterNames, and BodyFieldNames. It is shared by MatchesEndpointSelector
// and the CLI's templateApplies (pkg/runner) so the two selection paths cannot
// diverge on this logic. An unset field imposes no constraint; returns true when
// every set constraint is met.
func MatchesParamScopedSelectors(operation *model.Operation, selector templates.EndpointSelector) bool {
	if selector.HasQueryParameter && len(operation.QueryParams) == 0 {
		return false
	}
	if selector.HasBodyField && (operation.BodySchema == nil || len(operation.BodySchema.Properties) == 0) {
		return false
	}
	if len(selector.QueryParameterNames) > 0 && !OperationHasQueryParam(operation, selector.QueryParameterNames) {
		return false
	}
	if len(selector.BodyFieldNames) > 0 && !OperationHasBodyField(operation, selector.BodyFieldNames) {
		return false
	}
	return true
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
