package grpc

import (
	"encoding/json"
	"fmt"
)

// messageToJSON converts a message descriptor and data map to JSON bytes
func messageToJSON(msg *MessageDescriptor, data map[string]interface{}) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("message descriptor is nil")
	}

	// Simply marshal the data map to JSON
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message to JSON: %w", err)
	}

	return jsonBytes, nil
}

// jsonToMessageData converts JSON bytes to a message data map
func jsonToMessageData(msg *MessageDescriptor, jsonData []byte) (map[string]interface{}, error) {
	if msg == nil {
		return nil, fmt.Errorf("message descriptor is nil")
	}

	var data map[string]interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to message data: %w", err)
	}

	return data, nil
}

// generateDefaultMessageData creates a data map with default values for all fields
func generateDefaultMessageData(msg *MessageDescriptor) map[string]interface{} {
	if msg == nil {
		return make(map[string]interface{})
	}

	data := make(map[string]interface{})

	for _, field := range msg.Fields {
		data[field.Name] = getDefaultValue(field)
	}

	return data
}

// getDefaultValue returns the zero/default value for a field based on its type
func getDefaultValue(field *FieldDescriptor) interface{} {
	if field == nil {
		return ""
	}

	switch field.Type {
	case "TYPE_STRING":
		return ""
	case "TYPE_INT32", "TYPE_SINT32", "TYPE_SFIXED32":
		return int32(0)
	case "TYPE_INT64", "TYPE_SINT64", "TYPE_SFIXED64":
		return int64(0)
	case "TYPE_UINT32", "TYPE_FIXED32":
		return uint32(0)
	case "TYPE_UINT64", "TYPE_FIXED64":
		return uint64(0)
	case "TYPE_BOOL":
		return false
	case "TYPE_DOUBLE":
		return float64(0.0)
	case "TYPE_FLOAT":
		return float32(0.0)
	case "TYPE_BYTES":
		return []byte{}
	case "TYPE_MESSAGE", "TYPE_GROUP":
		return make(map[string]interface{})
	case "TYPE_ENUM":
		return int32(0) // Default enum value is 0
	default:
		return ""
	}
}
