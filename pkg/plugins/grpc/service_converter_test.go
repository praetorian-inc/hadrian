package grpc

import (
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertServicesToOperations(t *testing.T) {
	tests := []struct {
		name     string
		services []*ServiceDescriptor
		want     []*model.Operation
		wantErr  bool
	}{
		{
			name:     "empty services",
			services: []*ServiceDescriptor{},
			want:     []*model.Operation{},
			wantErr:  false,
		},
		{
			name: "single service with one method",
			services: []*ServiceDescriptor{
				{
					Name:     "UserService",
					FullName: "user.v1.UserService",
					Methods: []*MethodDescriptor{
						{
							Name:     "GetUser",
							FullName: "user.v1.UserService.GetUser",
							InputType: &MessageDescriptor{
								Name:     "GetUserRequest",
								FullName: "user.v1.GetUserRequest",
								Fields: []*FieldDescriptor{
									{Name: "id", Type: "TYPE_STRING", IsRequired: true},
								},
							},
							OutputType: &MessageDescriptor{
								Name:     "GetUserResponse",
								FullName: "user.v1.GetUserResponse",
								Fields: []*FieldDescriptor{
									{Name: "id", Type: "TYPE_STRING"},
									{Name: "name", Type: "TYPE_STRING"},
								},
							},
						},
					},
				},
			},
			want: []*model.Operation{
				{
					Method:             "GRPC",
					Path:               "/user.v1.UserService/GetUser",
					Protocol:           "grpc",
					SuccessStatus:      0,
					UnauthorizedStatus: 7,
					RequiresAuth:       false,
					ResourceType:       "User",
					OwnerField:         "id",
					Tags:               []string{"UserService", "GetUser", "User"},
					PathParams: []model.Parameter{
						{Name: "id", In: "grpc_field", Required: true, Type: "string"},
					},
				},
			},
		},
		{
			name: "method with auth patterns",
			services: []*ServiceDescriptor{
				{
					Name:     "UserService",
					FullName: "user.v1.UserService",
					Methods: []*MethodDescriptor{
						{
							Name:     "CreateUser",
							FullName: "user.v1.UserService.CreateUser",
							InputType: &MessageDescriptor{
								Name:     "CreateUserRequest",
								FullName: "user.v1.CreateUserRequest",
								Fields: []*FieldDescriptor{
									{Name: "name", Type: "TYPE_STRING"},
								},
							},
							OutputType: &MessageDescriptor{
								Name:     "CreateUserResponse",
								FullName: "user.v1.CreateUserResponse",
								Fields:   []*FieldDescriptor{},
							},
						},
					},
				},
			},
			want: []*model.Operation{
				{
					Method:             "GRPC",
					Path:               "/user.v1.UserService/CreateUser",
					Protocol:           "grpc",
					SuccessStatus:      0,
					UnauthorizedStatus: 7,
					RequiresAuth:       true, // "create" implies auth
					ResourceType:       "User",
					Tags:               []string{"UserService", "CreateUser", "User"},
				},
			},
		},
		{
			name: "multiple services",
			services: []*ServiceDescriptor{
				{
					Name:     "UserService",
					FullName: "user.v1.UserService",
					Methods: []*MethodDescriptor{
						{
							Name:     "GetUser",
							FullName: "user.v1.UserService.GetUser",
							InputType: &MessageDescriptor{
								Name:   "GetUserRequest",
								Fields: []*FieldDescriptor{},
							},
							OutputType: &MessageDescriptor{
								Name:   "GetUserResponse",
								Fields: []*FieldDescriptor{},
							},
						},
					},
				},
				{
					Name:     "PostService",
					FullName: "post.v1.PostService",
					Methods: []*MethodDescriptor{
						{
							Name:     "ListPosts",
							FullName: "post.v1.PostService.ListPosts",
							InputType: &MessageDescriptor{
								Name:   "ListPostsRequest",
								Fields: []*FieldDescriptor{},
							},
							OutputType: &MessageDescriptor{
								Name:   "ListPostsResponse",
								Fields: []*FieldDescriptor{},
							},
						},
					},
				},
			},
			want: []*model.Operation{
				{
					Method:             "GRPC",
					Path:               "/user.v1.UserService/GetUser",
					Protocol:           "grpc",
					SuccessStatus:      0,
					UnauthorizedStatus: 7,
					RequiresAuth:       false,
					ResourceType:       "User",
					Tags:               []string{"UserService", "GetUser", "User"},
				},
				{
					Method:             "GRPC",
					Path:               "/post.v1.PostService/ListPosts",
					Protocol:           "grpc",
					SuccessStatus:      0,
					UnauthorizedStatus: 7,
					RequiresAuth:       false,
					ResourceType:       "Posts",
					Tags:               []string{"PostService", "ListPosts", "Posts"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertServicesToOperations(tt.services)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Len(t, got, len(tt.want))

			for i, wantOp := range tt.want {
				assert.Equal(t, wantOp.Method, got[i].Method)
				assert.Equal(t, wantOp.Path, got[i].Path)
				assert.Equal(t, wantOp.Protocol, got[i].Protocol)
				assert.Equal(t, wantOp.SuccessStatus, got[i].SuccessStatus)
				assert.Equal(t, wantOp.UnauthorizedStatus, got[i].UnauthorizedStatus)
				assert.Equal(t, wantOp.RequiresAuth, got[i].RequiresAuth)
				assert.Equal(t, wantOp.ResourceType, got[i].ResourceType)
				assert.Equal(t, wantOp.Tags, got[i].Tags)

				if wantOp.OwnerField != "" {
					assert.Equal(t, wantOp.OwnerField, got[i].OwnerField)
				}

				if len(wantOp.PathParams) > 0 {
					require.Len(t, got[i].PathParams, len(wantOp.PathParams))
					for j, wantParam := range wantOp.PathParams {
						assert.Equal(t, wantParam.Name, got[i].PathParams[j].Name)
						assert.Equal(t, wantParam.In, got[i].PathParams[j].In)
						assert.Equal(t, wantParam.Required, got[i].PathParams[j].Required)
						assert.Equal(t, wantParam.Type, got[i].PathParams[j].Type)
					}
				}
			}
		})
	}
}

func TestInferAuthRequirement(t *testing.T) {
	tests := []struct {
		name       string
		methodName string
		want       bool
	}{
		// Public patterns (no auth)
		{"health check", "Health", false},
		{"ping", "Ping", false},
		{"version", "Version", false},
		{"status", "Status", false},
		{"list", "ListUsers", false},
		{"get", "GetUser", false},

		// Auth required patterns
		{"create", "CreateUser", true},
		{"update", "UpdateUser", true},
		{"delete", "DeleteUser", true},
		{"set", "SetPassword", true},
		{"add", "AddFriend", true},
		{"remove", "RemovePost", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := &MethodDescriptor{Name: tt.methodName}
			got := inferAuthRequirement(method)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractResourceType(t *testing.T) {
	tests := []struct {
		name       string
		outputName string
		want       string
	}{
		{"single word", "GetUserResponse", "User"},
		{"compound", "ListPostsResponse", "Posts"},
		{"no suffix", "User", "User"},
		{"empty", "", ""},
		{"multiple words", "GetBlogPostResponse", "BlogPost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := &MessageDescriptor{Name: tt.outputName}
			got := extractResourceType(output)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractOwnerField(t *testing.T) {
	tests := []struct {
		name   string
		fields []*FieldDescriptor
		want   string
	}{
		{
			name: "id field",
			fields: []*FieldDescriptor{
				{Name: "id", Type: "TYPE_STRING"},
				{Name: "name", Type: "TYPE_STRING"},
			},
			want: "id",
		},
		{
			name: "user_id field",
			fields: []*FieldDescriptor{
				{Name: "user_id", Type: "TYPE_STRING"},
				{Name: "name", Type: "TYPE_STRING"},
			},
			want: "user_id",
		},
		{
			name: "userId field",
			fields: []*FieldDescriptor{
				{Name: "userId", Type: "TYPE_STRING"},
				{Name: "name", Type: "TYPE_STRING"},
			},
			want: "userId",
		},
		{
			name: "no owner field",
			fields: []*FieldDescriptor{
				{Name: "name", Type: "TYPE_STRING"},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &MessageDescriptor{Fields: tt.fields}
			got := extractOwnerField(input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMapProtoTypeToJSON(t *testing.T) {
	tests := []struct {
		protoType string
		want      string
	}{
		{"TYPE_STRING", "string"},
		{"TYPE_INT32", "integer"},
		{"TYPE_INT64", "integer"},
		{"TYPE_BOOL", "boolean"},
		{"TYPE_DOUBLE", "number"},
		{"TYPE_FLOAT", "number"},
		{"TYPE_BYTES", "string"},
		{"TYPE_MESSAGE", "object"},
		{"TYPE_UNKNOWN", "string"},
	}

	for _, tt := range tests {
		t.Run(tt.protoType, func(t *testing.T) {
			got := mapProtoTypeToJSON(tt.protoType)
			assert.Equal(t, tt.want, got)
		})
	}
}
