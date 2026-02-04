package grpc

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

// ConvertServicesToOperations transforms gRPC service descriptors into Hadrian operations
func ConvertServicesToOperations(services []*ServiceDescriptor) ([]*model.Operation, error) {
	var operations []*model.Operation

	for _, service := range services {
		for _, method := range service.Methods {
			op := convertMethodToOperation(service, method)
			operations = append(operations, op)
		}
	}

	return operations, nil
}

// convertMethodToOperation creates a single operation from a gRPC method
func convertMethodToOperation(svc *ServiceDescriptor, method *MethodDescriptor) *model.Operation {
	op := &model.Operation{
		Method:             "GRPC",
		Path:               fmt.Sprintf("/%s/%s", svc.FullName, method.Name),
		Protocol:           "grpc",
		SuccessStatus:      0, // gRPC OK status
		UnauthorizedStatus: 7, // gRPC PERMISSION_DENIED status
		RequiresAuth:       inferAuthRequirement(method),
		ResourceType:       extractResourceType(method.OutputType),
		OwnerField:         extractOwnerField(method.InputType),
		Tags:               extractTags(svc, method),
	}

	// Convert input fields to path parameters
	if method.InputType != nil {
		for _, field := range method.InputType.Fields {
			param := model.Parameter{
				Name:     field.Name,
				In:       "grpc_field",
				Required: field.IsRequired,
				Type:     mapProtoTypeToJSON(field.Type),
			}
			op.PathParams = append(op.PathParams, param)
		}
	}

	return op
}

// inferAuthRequirement determines if a method requires authentication based on naming patterns
func inferAuthRequirement(method *MethodDescriptor) bool {
	name := strings.ToLower(method.Name)

	// Public patterns (no auth required)
	publicPatterns := []string{"health", "ping", "version", "status", "list", "get"}
	for _, pattern := range publicPatterns {
		if strings.HasPrefix(name, pattern) {
			return false
		}
	}

	// Mutation patterns (auth required)
	mutationPatterns := []string{"create", "update", "delete", "set", "add", "remove"}
	for _, pattern := range mutationPatterns {
		if strings.HasPrefix(name, pattern) {
			return true
		}
	}

	// Default to no auth for unknown patterns
	return false
}

// extractResourceType derives the resource type from the output message name
func extractResourceType(output *MessageDescriptor) string {
	if output == nil || output.Name == "" {
		return ""
	}

	name := output.Name

	// Remove common suffixes
	suffixes := []string{"Response", "Reply", "Output"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			name = strings.TrimSuffix(name, suffix)
			break
		}
	}

	// Remove method prefixes (Get, List, etc.)
	prefixes := []string{"Get", "List", "Create", "Update", "Delete"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			name = strings.TrimPrefix(name, prefix)
			break
		}
	}

	return name
}

// extractOwnerField finds the primary identifier field in the input message
func extractOwnerField(input *MessageDescriptor) string {
	if input == nil {
		return ""
	}

	// Common ID field patterns (lowercase for comparison)
	idPatterns := []string{"id", "user_id", "userid", "account_id", "accountid"}

	for _, field := range input.Fields {
		fieldLower := strings.ToLower(field.Name)
		for _, pattern := range idPatterns {
			if fieldLower == pattern {
				return field.Name
			}
		}
	}

	return ""
}

// extractTags generates descriptive tags from service and method information
func extractTags(svc *ServiceDescriptor, method *MethodDescriptor) []string {
	tags := []string{
		svc.Name,
		method.Name,
	}

	// Add resource type if available
	resourceType := extractResourceType(method.OutputType)
	if resourceType != "" {
		tags = append(tags, resourceType)
	}

	return tags
}

// mapProtoTypeToJSON converts protobuf types to JSON schema types
func mapProtoTypeToJSON(protoType string) string {
	switch protoType {
	case "TYPE_STRING", "TYPE_BYTES":
		return "string"
	case "TYPE_INT32", "TYPE_INT64", "TYPE_UINT32", "TYPE_UINT64",
		"TYPE_SINT32", "TYPE_SINT64", "TYPE_FIXED32", "TYPE_FIXED64",
		"TYPE_SFIXED32", "TYPE_SFIXED64":
		return "integer"
	case "TYPE_DOUBLE", "TYPE_FLOAT":
		return "number"
	case "TYPE_BOOL":
		return "boolean"
	case "TYPE_MESSAGE", "TYPE_GROUP":
		return "object"
	case "TYPE_ENUM":
		return "string"
	default:
		return "string" // Default fallback
	}
}
