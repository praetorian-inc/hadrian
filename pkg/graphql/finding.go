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

// OWASP Category mappings for GraphQL finding types (2023 format with descriptions)
const (
	CategoryAPI1 = "API1:2023 Broken Object Level Authorization"
	CategoryAPI4 = "API4:2023 Unrestricted Resource Consumption"
	CategoryAPI5 = "API5:2023 Broken Function Level Authorization"
	CategoryAPI8 = "API8:2023 Security Misconfiguration"
)
