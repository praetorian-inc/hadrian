package grpc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageToJSON(t *testing.T) {
	tests := []struct {
		name    string
		msg     *MessageDescriptor
		data    map[string]interface{}
		wantErr bool
	}{
		{
			name: "simple message",
			msg: &MessageDescriptor{
				Name: "GetUserRequest",
				Fields: []*FieldDescriptor{
					{Name: "id", Type: "TYPE_STRING"},
					{Name: "include_profile", Type: "TYPE_BOOL"},
				},
			},
			data: map[string]interface{}{
				"id":              "user-123",
				"include_profile": true,
			},
			wantErr: false,
		},
		{
			name: "with nested data",
			msg: &MessageDescriptor{
				Name: "CreateUserRequest",
				Fields: []*FieldDescriptor{
					{Name: "name", Type: "TYPE_STRING"},
					{Name: "age", Type: "TYPE_INT32"},
					{Name: "active", Type: "TYPE_BOOL"},
				},
			},
			data: map[string]interface{}{
				"name":   "Alice",
				"age":    float64(30), // JSON unmarshals numbers as float64
				"active": true,
			},
			wantErr: false,
		},
		{
			name: "empty data",
			msg: &MessageDescriptor{
				Name:   "EmptyRequest",
				Fields: []*FieldDescriptor{},
			},
			data:    map[string]interface{}{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := messageToJSON(tt.msg, tt.data)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Verify it's valid JSON by unmarshaling
			var result map[string]interface{}
			err = json.Unmarshal(jsonBytes, &result)
			require.NoError(t, err)

			// Verify all expected fields are present
			for key, expectedValue := range tt.data {
				actualValue, exists := result[key]
				assert.True(t, exists, "field %s should exist", key)
				assert.Equal(t, expectedValue, actualValue, "field %s mismatch", key)
			}
		})
	}
}

func TestJSONToMessageData(t *testing.T) {
	tests := []struct {
		name    string
		msg     *MessageDescriptor
		jsonStr string
		want    map[string]interface{}
		wantErr bool
	}{
		{
			name: "simple JSON",
			msg: &MessageDescriptor{
				Name: "Request",
				Fields: []*FieldDescriptor{
					{Name: "name", Type: "TYPE_STRING"},
					{Name: "count", Type: "TYPE_INT32"},
				},
			},
			jsonStr: `{"name": "test", "count": 42}`,
			want: map[string]interface{}{
				"name":  "test",
				"count": float64(42), // JSON numbers unmarshal to float64
			},
			wantErr: false,
		},
		{
			name: "with boolean",
			msg: &MessageDescriptor{
				Name: "Request",
				Fields: []*FieldDescriptor{
					{Name: "enabled", Type: "TYPE_BOOL"},
					{Name: "value", Type: "TYPE_STRING"},
				},
			},
			jsonStr: `{"enabled": true, "value": "test"}`,
			want: map[string]interface{}{
				"enabled": true,
				"value":   "test",
			},
			wantErr: false,
		},
		{
			name: "invalid JSON",
			msg: &MessageDescriptor{
				Name:   "Request",
				Fields: []*FieldDescriptor{},
			},
			jsonStr: `{invalid json}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := jsonToMessageData(tt.msg, []byte(tt.jsonStr))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, data)
		})
	}
}

func TestGenerateDefaultMessageData(t *testing.T) {
	tests := []struct {
		name string
		msg  *MessageDescriptor
	}{
		{
			name: "various types",
			msg: &MessageDescriptor{
				Name: "CreateUserRequest",
				Fields: []*FieldDescriptor{
					{Name: "name", Type: "TYPE_STRING"},
					{Name: "age", Type: "TYPE_INT32"},
					{Name: "active", Type: "TYPE_BOOL"},
					{Name: "score", Type: "TYPE_DOUBLE"},
				},
			},
		},
		{
			name: "empty message",
			msg: &MessageDescriptor{
				Name:   "EmptyRequest",
				Fields: []*FieldDescriptor{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := generateDefaultMessageData(tt.msg)

			assert.NotNil(t, data)

			// Verify all fields are present
			for _, field := range tt.msg.Fields {
				value, exists := data[field.Name]
				assert.True(t, exists, "field %s should have default value", field.Name)
				assert.NotNil(t, value, "default value for %s should not be nil", field.Name)
			}
		})
	}
}

func TestGetDefaultValue(t *testing.T) {
	tests := []struct {
		field *FieldDescriptor
		want  interface{}
	}{
		{&FieldDescriptor{Name: "str", Type: "TYPE_STRING"}, ""},
		{&FieldDescriptor{Name: "num", Type: "TYPE_INT32"}, int32(0)},
		{&FieldDescriptor{Name: "num64", Type: "TYPE_INT64"}, int64(0)},
		{&FieldDescriptor{Name: "bool", Type: "TYPE_BOOL"}, false},
		{&FieldDescriptor{Name: "dbl", Type: "TYPE_DOUBLE"}, float64(0.0)},
		{&FieldDescriptor{Name: "flt", Type: "TYPE_FLOAT"}, float32(0.0)},
		{&FieldDescriptor{Name: "bytes", Type: "TYPE_BYTES"}, []byte{}},
		{&FieldDescriptor{Name: "msg", Type: "TYPE_MESSAGE"}, map[string]interface{}{}},
		{&FieldDescriptor{Name: "unknown", Type: "TYPE_UNKNOWN"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.field.Type, func(t *testing.T) {
			got := getDefaultValue(tt.field)
			assert.Equal(t, tt.want, got)
		})
	}
}
