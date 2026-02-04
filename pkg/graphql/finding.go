package graphql

// FindingType represents the type of security finding (GraphQL-specific enum)
// These map to model.Finding.Name field
type FindingType string

const (
	// FindingTypeIntrospectionDisclosure indicates GraphQL introspection is enabled
	FindingTypeIntrospectionDisclosure FindingType = "introspection-disclosure"
	// FindingTypeNoDepthLimit indicates no query depth limit is enforced
	FindingTypeNoDepthLimit FindingType = "no-depth-limit"
	// FindingTypeNoBatchingLimit indicates no batching limit is enforced
	FindingTypeNoBatchingLimit FindingType = "no-batching-limit"
	// FindingTypeNoComplexityLimit indicates no complexity limit is enforced
	FindingTypeNoComplexityLimit FindingType = "no-complexity-limit"
	// FindingTypeBOLA indicates Broken Object Level Authorization vulnerability
	FindingTypeBOLA FindingType = "bola"
	// FindingTypeBFLA indicates Broken Function Level Authorization vulnerability
	FindingTypeBFLA FindingType = "bfla"
)

// String returns the string representation of FindingType
func (f FindingType) String() string {
	return string(f)
}

// OWASP Category mappings for GraphQL finding types
const (
	CategoryAPI3 = "API3" // Excessive Data Exposure (introspection)
	CategoryAPI4 = "API4" // Lack of Resources & Rate Limiting (depth/batch limits)
	CategoryAPI5 = "API5" // BFLA
	CategoryAPI1 = "API1" // BOLA
)
