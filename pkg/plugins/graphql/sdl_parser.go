// pkg/plugins/graphql/sdl_parser.go
package graphql

import (
	"github.com/praetorian-inc/hadrian/pkg/graphql"
)

// ParseSDL parses a GraphQL SDL string into our Schema type.
// Delegates to the canonical implementation in pkg/graphql.
func ParseSDL(sdl string) (*graphql.Schema, error) {
	return graphql.ParseSDL(sdl)
}
