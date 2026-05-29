// VULNERABLE GRAPHQL SERVER — FOR TESTING ONLY
//
// This binary is an INTENTIONALLY INSECURE in-house replacement for the
// DVGA (Damn Vulnerable GraphQL App) Docker image. It exposes the same
// GraphQL surface so Hadrian's built-in templates fire against it without
// requiring Docker in devcontainer environments.
//
// WARNING: This server performs REAL OS command execution and REAL file
// writes with path-traversal unsanitised. DO NOT expose on a public network.
// Run it only in isolated test environments.
//
// Intentional vulnerabilities mirrored from DVGA:
//   - BOLA: paste(id) and editPaste/deletePaste have no ownership checks
//   - BFLA: deleteAllPastes has no authorisation
//   - Sensitive data exposure: UserObject.password is directly readable
//   - Command injection: systemDiagnostics(cmd) executes sh -c <cmd>
//   - Path traversal: uploadPaste(filename) writes without sanitising ".."
//   - Error disclosure: verbose internal error details returned to caller
//   - No depth / alias / complexity limits (alias-DoS checks fire)
//   - Introspection always enabled
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/graphql-go/graphql"
)

// ============================================================================
// Constants & global state
// ============================================================================

// jwtSecret is INTENTIONALLY INSECURE: hardcoded weak secret for test use only.
var jwtSecret = []byte("dvga-vulnerable-secret-do-not-use-in-production")

// uploadDir is the base directory for uploadPaste. A sub-directory of the OS
// temp dir so the process does not need elevated privileges.
var uploadDir string

// Seed data stores (in-memory, reset-capable).
var (
	mu          sync.Mutex
	pastes      []Paste
	users       []UserRecord
	nextPasteID int // monotonic counter; avoids ID collision after deletes
)

// ============================================================================
// Data models
// ============================================================================

// Paste models a user-submitted snippet of text.
type Paste struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Public    bool   `json:"public"`
	UserAgent string `json:"userAgent"`
	IPAddr    string `json:"ipAddr"`
	OwnerID   int    `json:"ownerId"`
	Burn      bool   `json:"burn"`
}

// UserRecord models an account.
// INTENTIONALLY INSECURE: Password is exposed in the GraphQL schema.
type UserRecord struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"` // INTENTIONALLY INSECURE: password exposed
	Role     string `json:"role"`
}

// ============================================================================
// Seed data
// ============================================================================

func initData() {
	mu.Lock()
	defer mu.Unlock()

	// Seed users — INTENTIONALLY INSECURE: hardcoded credentials for this vulnerable test server.
	// These are NOT real credentials. This server exists solely to be a test target for Hadrian.
	users = []UserRecord{
		{ID: 1, Username: "admin", Password: "admin123", Role: "admin"},
		{ID: 2, Username: "user1", Password: "user1pass", Role: "user"},
		{ID: 3, Username: "user2", Password: "user2pass", Role: "user"},
	}

	// Seed pastes.
	// user1 (id=2) owns pastes 1 and 3; user2 (id=3) owns paste 2; admin (id=1) owns paste 4.
	// BOLA templates use paste 1 (delete) and paste 3 (edit) — both victim-owned, distinct.
	pastes = []Paste{
		{ID: 1, Title: "User1 Private Paste", Content: "Secret content owned by user1", Public: false, UserAgent: "Mozilla/5.0", IPAddr: "127.0.0.1", OwnerID: 2, Burn: false},
		{ID: 2, Title: "User2 Private Paste", Content: "Secret content owned by user2", Public: false, UserAgent: "Mozilla/5.0", IPAddr: "127.0.0.1", OwnerID: 3, Burn: false},
		{ID: 3, Title: "User1 Second Paste", Content: "Another secret owned by user1", Public: false, UserAgent: "Mozilla/5.0", IPAddr: "127.0.0.1", OwnerID: 2, Burn: false},
		{ID: 4, Title: "Public Paste Beta", Content: "More publicly visible content", Public: true, UserAgent: "curl/7.0", IPAddr: "10.0.0.2", OwnerID: 1, Burn: false},
	}
	// Initialise monotonic counter to max seed ID + 1
	nextPasteID = 5
}

// ============================================================================
// JWT helpers
// ============================================================================

// createJWT mints an HS256 token for the given user.
func createJWT(u *UserRecord) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  u.ID,
		"username": u.Username,
		"role":     u.Role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// parseJWT validates a token string and returns the matching UserRecord.
// Returns nil (no error) when the token is absent or invalid — resolvers
// simply receive no current user, which is the intended BOLA bug.
func parseJWT(tokenString string) *UserRecord {
	if tokenString == "" {
		return nil
	}
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}
	uidF, ok2 := claims["user_id"].(float64)
	if !ok2 {
		return nil
	}
	userID := int(uidF)
	mu.Lock()
	defer mu.Unlock()
	for i := range users {
		if users[i].ID == userID {
			return &users[i]
		}
	}
	return nil
}

// ============================================================================
// Context helpers
// ============================================================================

type contextKey string

const ctxUser contextKey = "current_user"

// currentUser extracts the authenticated user from the resolver context.
func currentUser(p graphql.ResolveParams) *UserRecord {
	u, _ := p.Context.Value(ctxUser).(*UserRecord)
	return u
}

// ============================================================================
// GraphQL type definitions
// ============================================================================

// ownerType and pasteType reference each other — use FieldsThunk for the
// circular reference to avoid a nil-pointer at init time.
// buildTypesOnce ensures the graphql.Object instances are constructed exactly
// once per process; graphql-go rejects duplicate named types.

var ownerType *graphql.Object
var pasteType *graphql.Object
var buildTypesOnce sync.Once

func buildTypes() {
	buildTypesOnce.Do(func() { buildTypesImpl() })
}

func buildTypesImpl() {
	ownerType = graphql.NewObject(graphql.ObjectConfig{
		Name: "OwnerObject",
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			return graphql.Fields{
				"id": &graphql.Field{Type: graphql.NewNonNull(graphql.ID)},
				"name": &graphql.Field{
					Type: graphql.String,
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						if u, ok := p.Source.(*UserRecord); ok {
							return u.Username, nil
						}
						return nil, nil
					},
				},
				"pastes": &graphql.Field{
					Type: graphql.NewList(pasteType),
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						if u, ok := p.Source.(*UserRecord); ok {
							mu.Lock()
							defer mu.Unlock()
							var result []Paste
							for _, paste := range pastes {
								if paste.OwnerID == u.ID {
									result = append(result, paste)
								}
							}
							return result, nil
						}
						return nil, nil
					},
				},
			}
		}),
	})

	pasteType = graphql.NewObject(graphql.ObjectConfig{
		Name: "PasteObject",
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			return graphql.Fields{
				"id":        &graphql.Field{Type: graphql.NewNonNull(graphql.ID)},
				"title":     &graphql.Field{Type: graphql.String},
				"content":   &graphql.Field{Type: graphql.String},
				"public":    &graphql.Field{Type: graphql.Boolean},
				"userAgent": &graphql.Field{Type: graphql.String},
				"ipAddr":    &graphql.Field{Type: graphql.String},
				"ownerId":   &graphql.Field{Type: graphql.Int},
				"burn":      &graphql.Field{Type: graphql.Boolean},
				"owner": &graphql.Field{
					Type: ownerType,
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						paste, ok := p.Source.(Paste)
						if !ok {
							return nil, nil
						}
						mu.Lock()
						defer mu.Unlock()
						for i := range users {
							if users[i].ID == paste.OwnerID {
								return &users[i], nil
							}
						}
						return nil, nil
					},
				},
			}
		}),
	})
}

// userObjectType exposes the password field — INTENTIONALLY INSECURE.
var userObjectType = graphql.NewObject(graphql.ObjectConfig{
	Name: "UserObject",
	Fields: graphql.Fields{
		"id": &graphql.Field{Type: graphql.NewNonNull(graphql.ID)},
		"username": &graphql.Field{
			Type: graphql.String,
			Args: graphql.FieldConfigArgument{
				"capitalize": &graphql.ArgumentConfig{Type: graphql.Boolean},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				u, ok := p.Source.(*UserRecord)
				if !ok {
					return nil, nil
				}
				if cap, _ := p.Args["capitalize"].(bool); cap {
					if len(u.Username) == 0 {
						return "", nil
					}
					return strings.ToUpper(u.Username[:1]) + u.Username[1:], nil
				}
				return u.Username, nil
			},
		},
		// INTENTIONALLY INSECURE: password exposed in schema
		"password": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
	},
})

var loginType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Login",
	Fields: graphql.Fields{
		"accessToken":  &graphql.Field{Type: graphql.String},
		"refreshToken": &graphql.Field{Type: graphql.String},
	},
})

var createPasteType = graphql.NewObject(graphql.ObjectConfig{
	Name: "CreatePaste",
	Fields: (graphql.FieldsThunk)(func() graphql.Fields {
		return graphql.Fields{
			"paste": &graphql.Field{Type: pasteType},
		}
	}),
})

var editPasteType = graphql.NewObject(graphql.ObjectConfig{
	Name: "EditPaste",
	Fields: (graphql.FieldsThunk)(func() graphql.Fields {
		return graphql.Fields{
			"paste": &graphql.Field{Type: pasteType},
		}
	}),
})

var deletePasteType = graphql.NewObject(graphql.ObjectConfig{
	Name: "DeletePaste",
	Fields: graphql.Fields{
		"result": &graphql.Field{Type: graphql.Boolean},
	},
})

var uploadPasteType = graphql.NewObject(graphql.ObjectConfig{
	Name: "UploadPaste",
	Fields: graphql.Fields{
		"content":  &graphql.Field{Type: graphql.String},
		"filename": &graphql.Field{Type: graphql.String},
		"result":   &graphql.Field{Type: graphql.String},
	},
})

var createUserType = graphql.NewObject(graphql.ObjectConfig{
	Name: "CreateUser",
	Fields: graphql.Fields{
		"user": &graphql.Field{Type: userObjectType},
	},
})

// ============================================================================
// Schema construction
// ============================================================================

func buildSchema() (graphql.Schema, error) {
	buildTypes()

	queryType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			// pastes — list with optional filtering
			"pastes": &graphql.Field{
				Type: graphql.NewList(pasteType),
				Args: graphql.FieldConfigArgument{
					"public": &graphql.ArgumentConfig{Type: graphql.Boolean},
					"limit":  &graphql.ArgumentConfig{Type: graphql.Int},
					"filter": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					mu.Lock()
					defer mu.Unlock()
					result := make([]Paste, 0, len(pastes))
					for _, paste := range pastes {
						if pub, ok := p.Args["public"].(bool); ok && paste.Public != pub {
							continue
						}
						if filter, ok := p.Args["filter"].(string); ok && filter != "" {
							if !strings.Contains(paste.Title, filter) && !strings.Contains(paste.Content, filter) {
								continue
							}
						}
						result = append(result, paste)
					}
					if limit, ok := p.Args["limit"].(int); ok && limit > 0 && len(result) > limit {
						result = result[:limit]
					}
					return result, nil
				},
			},

			// paste — BOLA: no ownership check
			"paste": &graphql.Field{
				Type: pasteType,
				Args: graphql.FieldConfigArgument{
					"id":    &graphql.ArgumentConfig{Type: graphql.Int},
					"title": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					// BOLA VULNERABILITY: no ownership check — any authenticated user
					// (or even unauthenticated) can retrieve any paste by ID.
					mu.Lock()
					defer mu.Unlock()
					for _, paste := range pastes {
						if id, ok := p.Args["id"].(int); ok && paste.ID == id {
							return paste, nil
						}
						if title, ok := p.Args["title"].(string); ok && title != "" && paste.Title == title {
							return paste, nil
						}
					}
					return nil, nil
				},
			},

			// users — exposes password field
			"users": &graphql.Field{
				Type: graphql.NewList(userObjectType),
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{Type: graphql.Int},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					mu.Lock()
					defer mu.Unlock()
					var result []*UserRecord
					for i := range users {
						if id, ok := p.Args["id"].(int); ok && users[i].ID != id {
							continue
						}
						result = append(result, &users[i])
					}
					return result, nil
				},
			},

			// me — returns current user from token
			"me": &graphql.Field{
				Type: userObjectType,
				Args: graphql.FieldConfigArgument{
					"token": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					// Prefer token arg over header-injected user
					if tok, ok := p.Args["token"].(string); ok && tok != "" {
						return parseJWT(tok), nil
					}
					return currentUser(p), nil
				},
			},

			// systemHealth — information disclosure
			"systemHealth": &graphql.Field{
				Type: graphql.String,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					return "System is up and running", nil
				},
			},

			// systemDebug — INTENTIONALLY INSECURE: information disclosure
			"systemDebug": &graphql.Field{
				Type: graphql.String,
				Args: graphql.FieldConfigArgument{
					"arg": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					arg, _ := p.Args["arg"].(string)
					// INTENTIONALLY INSECURE: exposes internal debug info
					return fmt.Sprintf("DEBUG: arg=%q pid=%d uptime=running", arg, os.Getpid()), nil
				},
			},

			// systemDiagnostics — INTENTIONALLY VULNERABLE: real command execution
			"systemDiagnostics": &graphql.Field{
				Type: graphql.String,
				Args: graphql.FieldConfigArgument{
					"username": &graphql.ArgumentConfig{Type: graphql.String},
					"password": &graphql.ArgumentConfig{Type: graphql.String},
					"cmd":      &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					cmd, _ := p.Args["cmd"].(string)
					if cmd == "" {
						return "", nil
					}
					// INTENTIONALLY VULNERABLE: real command execution — do NOT sanitise.
					// This matches DVGA's behaviour and allows Hadrian's command-injection
					// templates to verify real RCE.
					out, err := exec.Command("sh", "-c", cmd).CombinedOutput() //nolint:gosec
					if err != nil {
						// INTENTIONALLY VERBOSE: include error detail in response
						return string(out) + "\nerror: " + err.Error(), nil
					}
					return string(out), nil
				},
			},

			// deleteAllPastes — BFLA: dangerous, no authorisation
			"deleteAllPastes": &graphql.Field{
				Type: graphql.Boolean,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					// BFLA VULNERABILITY: no authorisation check — any caller can wipe all pastes.
					mu.Lock()
					pastes = []Paste{}
					mu.Unlock()
					return true, nil
				},
			},
		},
	})

	mutationType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			// login — returns a real HS256 JWT accessToken
			"login": &graphql.Field{
				Type: loginType,
				Args: graphql.FieldConfigArgument{
					"username": &graphql.ArgumentConfig{Type: graphql.String},
					"password": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					username, _ := p.Args["username"].(string)
					password, _ := p.Args["password"].(string)
					mu.Lock()
					var found *UserRecord
					for i := range users {
						if users[i].Username == username && users[i].Password == password {
							found = &users[i]
							break
						}
					}
					mu.Unlock()
					if found == nil {
						// INTENTIONALLY VERBOSE: expose reason for test visibility
						return nil, fmt.Errorf("login failed: invalid credentials for user %q", username)
					}
					accessToken, err := createJWT(found)
					if err != nil {
						return nil, fmt.Errorf("token generation error: %w", err)
					}
					return map[string]interface{}{
						"accessToken":  accessToken,
						"refreshToken": "refresh-" + accessToken[:16],
					}, nil
				},
			},

			// createPaste
			"createPaste": &graphql.Field{
				Type: createPasteType,
				Args: graphql.FieldConfigArgument{
					"title":   &graphql.ArgumentConfig{Type: graphql.String},
					"content": &graphql.ArgumentConfig{Type: graphql.String},
					"public":  &graphql.ArgumentConfig{Type: graphql.Boolean},
					"burn":    &graphql.ArgumentConfig{Type: graphql.Boolean},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					ownerID := 0
					if u := currentUser(p); u != nil {
						ownerID = u.ID
					}
					// Context values are stored under the typed contextKey by the
					// HTTP handler; read them with the same typed key and comma-ok
					// so a missing value is non-fatal rather than a nil panic.
					userAgent, _ := p.Context.Value(contextKey("user_agent")).(string)
					ipAddr, _ := p.Context.Value(contextKey("remote_addr")).(string)
					mu.Lock()
					newPaste := Paste{
						ID:        nextPasteID,
						Title:     stringArg(p, "title"),
						Content:   stringArg(p, "content"),
						Public:    boolArg(p, "public"),
						Burn:      boolArg(p, "burn"),
						UserAgent: userAgent,
						IPAddr:    ipAddr,
						OwnerID:   ownerID,
					}
					nextPasteID++
					pastes = append(pastes, newPaste)
					mu.Unlock()
					return map[string]interface{}{"paste": newPaste}, nil
				},
			},

			// editPaste — BOLA: no ownership check
			"editPaste": &graphql.Field{
				Type: editPasteType,
				Args: graphql.FieldConfigArgument{
					"id":      &graphql.ArgumentConfig{Type: graphql.Int},
					"title":   &graphql.ArgumentConfig{Type: graphql.String},
					"content": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id, _ := p.Args["id"].(int)
					mu.Lock()
					defer mu.Unlock()
					for i := range pastes {
						if pastes[i].ID == id {
							// BOLA VULNERABILITY: no ownership check
							if title, ok := p.Args["title"].(string); ok {
								pastes[i].Title = title
							}
							if content, ok := p.Args["content"].(string); ok {
								pastes[i].Content = content
							}
							return map[string]interface{}{"paste": pastes[i]}, nil
						}
					}
					// INTENTIONALLY VERBOSE: expose which ID was not found
					return nil, fmt.Errorf("paste id=%d not found", id)
				},
			},

			// deletePaste — BOLA: no ownership check
			"deletePaste": &graphql.Field{
				Type: deletePasteType,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{Type: graphql.Int},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id, _ := p.Args["id"].(int)
					mu.Lock()
					defer mu.Unlock()
					for i, paste := range pastes {
						if paste.ID == id {
							// BOLA VULNERABILITY: no ownership check
							pastes = append(pastes[:i], pastes[i+1:]...)
							return map[string]interface{}{"result": true}, nil
						}
					}
					return map[string]interface{}{"result": false}, nil
				},
			},

			// uploadPaste — INTENTIONALLY VULNERABLE: path traversal via filename
			"uploadPaste": &graphql.Field{
				Type: uploadPasteType,
				Args: graphql.FieldConfigArgument{
					"content":  &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"filename": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					content, _ := p.Args["content"].(string)
					filename, _ := p.Args["filename"].(string)

					// INTENTIONALLY VULNERABLE: path traversal — write to filepath.Join(uploadDir, filename)
					// WITHOUT sanitising ".." sequences. This matches DVGA's behaviour and allows
					// Hadrian's path-traversal templates to verify real file writes.
					dest := filepath.Join(uploadDir, filename) //nolint:gosec
					if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
						// INTENTIONALLY VERBOSE: include internal path in error
						return nil, fmt.Errorf("mkdir error for %q: %w", filepath.Dir(dest), err)
					}
					if err := os.WriteFile(dest, []byte(content), 0644); err != nil { //nolint:gosec
						return nil, fmt.Errorf("write error for %q: %w", dest, err)
					}
					return map[string]interface{}{
						"content":  content,
						"filename": dest,
						"result":   "success",
					}, nil
				},
			},

			// createUser
			"createUser": &graphql.Field{
				Type: createUserType,
				Args: graphql.FieldConfigArgument{
					"userData": &graphql.ArgumentConfig{
						Type: graphql.NewInputObject(graphql.InputObjectConfig{
							Name: "UserInput",
							Fields: graphql.InputObjectConfigFieldMap{
								"username": &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
								"email":    &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
								"password": &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
							},
						}),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userData, _ := p.Args["userData"].(map[string]interface{})
					if userData == nil {
						return nil, fmt.Errorf("userData is required")
					}
					username, _ := userData["username"].(string)
					password, _ := userData["password"].(string)
					mu.Lock()
					newUser := &UserRecord{
						ID:       len(users) + 1,
						Username: username,
						Password: password,
						Role:     "user",
					}
					users = append(users, *newUser)
					mu.Unlock()
					return map[string]interface{}{"user": newUser}, nil
				},
			},

			// promoteUser — BFLA: admin-only role change with NO authorisation
			// check. Any authenticated (even low-privilege) caller can escalate
			// any account's role — including their own — to admin. This is the
			// "BFLA on admin mutation" vector: a privileged function exposed
			// without a function-level authorization gate.
			"promoteUser": &graphql.Field{
				Type: userObjectType,
				Args: graphql.FieldConfigArgument{
					"username": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"role":     &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					// BFLA VULNERABILITY: no check that the caller is an admin.
					username := stringArg(p, "username")
					role := stringArg(p, "role")
					mu.Lock()
					defer mu.Unlock()
					for i := range users {
						if users[i].Username == username {
							users[i].Role = role
							return &users[i], nil
						}
					}
					return nil, fmt.Errorf("promoteUser failed: user %q not found", username)
				},
			},
		},
	})

	return graphql.NewSchema(graphql.SchemaConfig{
		Query:    queryType,
		Mutation: mutationType,
	})
}

// ============================================================================
// Small resolver helpers
// ============================================================================

func stringArg(p graphql.ResolveParams, key string) string {
	v, _ := p.Args[key].(string)
	return v
}

func boolArg(p graphql.ResolveParams, key string) bool {
	v, _ := p.Args[key].(bool)
	return v
}

// ============================================================================
// HTTP handler
// ============================================================================

// graphqlRequest is the JSON body sent to POST /graphql.
type graphqlRequest struct {
	Query         string                 `json:"query"`
	Variables     map[string]interface{} `json:"variables"`
	OperationName string                 `json:"operationName"`
}

func makeGraphQLHandler(schema graphql.Schema) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "only POST is supported", http.StatusMethodNotAllowed)
			return
		}

		// Parse JSON body
		var req graphqlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Inject current user from Bearer token into context — but DO NOT
		// enforce auth in resolvers (that is the intentional BOLA bug).
		var currentUserVal *UserRecord
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			tok := strings.TrimPrefix(authHeader, "Bearer ")
			currentUserVal = parseJWT(tok)
		}

		ctx := context.WithValue(r.Context(), ctxUser, currentUserVal)
		ctx = context.WithValue(ctx, contextKey("user_agent"), r.Header.Get("User-Agent"))
		ctx = context.WithValue(ctx, contextKey("remote_addr"), r.RemoteAddr)

		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  req.Query,
			VariableValues: req.Variables,
			OperationName:  req.OperationName,
			Context:        ctx,
		})

		// INTENTIONALLY VERBOSE: always include full error detail in response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			log.Printf("encode error: %v", err)
		}
	}
}

// ============================================================================
// Entry point
// ============================================================================

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5013"
	}

	// Create upload directory — INTENTIONALLY INSECURE: path traversal base dir
	var err error
	uploadDir, err = os.MkdirTemp("", "vuln-graphql-uploads-*")
	if err != nil {
		log.Fatalf("failed to create upload dir: %v", err)
	}

	// Seed in-memory data
	initData()

	// Build schema
	schema, err := buildSchema()
	if err != nil {
		log.Fatalf("failed to build GraphQL schema: %v", err)
	}

	gqlHandler := makeGraphQLHandler(schema)

	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", gqlHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"healthy"}`)
	})
	mux.HandleFunc("/api/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		initData()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"message":"data reset to initial state","pastes":"4","users":"3"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, "Vulnerable GraphQL Server — FOR TESTING ONLY")
		fmt.Fprintln(w, "Endpoint: POST /graphql")
		fmt.Fprintln(w, "Health:   GET  /health")
		fmt.Fprintln(w, "Reset:    POST /api/reset")
	})

	// Print startup banner
	fmt.Println("===========================================")
	fmt.Println("VULNERABLE GRAPHQL SERVER — FOR TESTING ONLY")
	fmt.Println("WARNING: Real command execution + file writes!")
	fmt.Println("===========================================")
	fmt.Printf("Port:       %s\n", port)
	fmt.Printf("Upload dir: %s\n", uploadDir)
	fmt.Println()
	fmt.Println("--- Seed Users ---")
	for _, u := range users {
		fmt.Printf("  %s (id=%d, role=%s, password=%s)\n", u.Username, u.ID, u.Role, u.Password)
	}
	fmt.Println()
	fmt.Println("--- Intentional Vulnerabilities ---")
	fmt.Println("  BOLA:               paste(id), editPaste, deletePaste — no owner check")
	fmt.Println("  BFLA:               deleteAllPastes, promoteUser — admin ops, no authz")
	fmt.Println("  Sensitive data:     users{password} — plaintext in schema")
	fmt.Println("  Command injection:  systemDiagnostics(cmd) — exec.Command(sh,-c,cmd)")
	fmt.Println("  Path traversal:     uploadPaste(filename) — unsanitised ..")
	fmt.Println("  Error disclosure:   verbose internal errors in GraphQL response")
	fmt.Println("  No depth limits:    alias-DoS / field-duplication checks fire")
	fmt.Println("  Introspection:      always enabled")
	fmt.Println("===========================================")
	fmt.Println()

	addr := "127.0.0.1:" + port
	log.Printf("Listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
