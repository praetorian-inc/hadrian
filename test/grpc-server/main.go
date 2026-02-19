package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	pb "github.com/praetorian-inc/hadrian/test/grpc-server/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// In-memory data store
type Store struct {
	users    map[string]*pb.UserResponse
	profiles map[string]*pb.ProfileResponse
	orders   map[string]*pb.OrderResponse
	config   *pb.SystemConfigResponse
}

var store *Store

func init() {
	store = &Store{
		users:    make(map[string]*pb.UserResponse),
		profiles: make(map[string]*pb.ProfileResponse),
		orders:   make(map[string]*pb.OrderResponse),
		config: &pb.SystemConfigResponse{
			DatabaseUrl:     "postgresql://admin:secret@localhost:5432/prod",
			ApiSecret:       "sk_live_51HxJKLMNOP123456789ABCDEFGH",
			DebugMode:       true,
			MaintenanceMode: false,
			AllowedOrigins:  []string{"*"},
		},
	}

	// Seed users
	store.users["1"] = &pb.UserResponse{
		Id:            "1",
		Username:      "admin",
		Email:         "admin@example.com",
		Role:          "admin",
		CreatedAt:     time.Now().Add(-365 * 24 * time.Hour).Format(time.RFC3339),
		InternalNotes: "Root admin account - full privileges",
	}
	store.users["2"] = &pb.UserResponse{
		Id:            "2",
		Username:      "user1",
		Email:         "user1@example.com",
		Role:          "user",
		CreatedAt:     time.Now().Add(-180 * 24 * time.Hour).Format(time.RFC3339),
		InternalNotes: "Regular user - pending background check",
	}
	store.users["3"] = &pb.UserResponse{
		Id:            "3",
		Username:      "user2",
		Email:         "user2@example.com",
		Role:          "user",
		CreatedAt:     time.Now().Add(-90 * 24 * time.Hour).Format(time.RFC3339),
		InternalNotes: "Flagged for suspicious activity - monitor closely",
	}

	// Seed profiles
	store.profiles["1"] = &pb.ProfileResponse{
		Id:          "1",
		UserId:      "1",
		FullName:    "Admin User",
		Ssn:         "123-45-6789",
		PhoneNumber: "555-0001",
		Address:     "123 Admin Street, Admin City, AC 12345",
		CreditScore: 850,
	}
	store.profiles["2"] = &pb.ProfileResponse{
		Id:          "2",
		UserId:      "2",
		FullName:    "User One",
		Ssn:         "234-56-7890",
		PhoneNumber: "555-0002",
		Address:     "456 User Avenue, User Town, UT 23456",
		CreditScore: 720,
	}
	store.profiles["3"] = &pb.ProfileResponse{
		Id:          "3",
		UserId:      "3",
		FullName:    "User Two",
		Ssn:         "345-67-8901",
		PhoneNumber: "555-0003",
		Address:     "789 User Boulevard, User City, UC 34567",
		CreditScore: 680,
	}

	// Seed orders
	store.orders["1"] = &pb.OrderResponse{
		Id:               "1",
		UserId:           "1",
		ProductId:        "prod-001",
		Quantity:         2,
		TotalAmount:      299.98,
		Status:           "delivered",
		CreatedAt:        time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
		PaymentCardLast4: "4242",
	}
	store.orders["2"] = &pb.OrderResponse{
		Id:               "2",
		UserId:           "2",
		ProductId:        "prod-002",
		Quantity:         1,
		TotalAmount:      49.99,
		Status:           "shipped",
		CreatedAt:        time.Now().Add(-7 * 24 * time.Hour).Format(time.RFC3339),
		PaymentCardLast4: "5555",
	}
	store.orders["3"] = &pb.OrderResponse{
		Id:               "3",
		UserId:           "2",
		ProductId:        "prod-003",
		Quantity:         3,
		TotalAmount:      89.97,
		Status:           "processing",
		CreatedAt:        time.Now().Add(-2 * 24 * time.Hour).Format(time.RFC3339),
		PaymentCardLast4: "5555",
	}
	store.orders["4"] = &pb.OrderResponse{
		Id:               "4",
		UserId:           "3",
		ProductId:        "prod-004",
		Quantity:         1,
		TotalAmount:      199.99,
		Status:           "pending",
		CreatedAt:        time.Now().Add(-1 * 24 * time.Hour).Format(time.RFC3339),
		PaymentCardLast4: "1234",
	}
}

// Token-based authentication (hardcoded tokens for testing)
var tokens = map[string]string{
	"admin-token-12345": "1", // admin user
	"user1-token-67890": "2", // user1
	"user2-token-abcde": "3", // user2
}

// getUserIDFromToken extracts user ID from bearer token
// VULNERABLE: Accepts requests without proper token validation on some endpoints
func getUserIDFromToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	token := strings.TrimPrefix(authHeaders[0], "Bearer ")
	userID, ok := tokens[token]
	if !ok {
		return "", status.Error(codes.Unauthenticated, "invalid token")
	}

	return userID, nil
}

// UserServiceServer implementation
type userServiceServer struct {
	pb.UnimplementedUserServiceServer
}

func (s *userServiceServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	// VULNERABLE: Only checks if user is authenticated, NOT if they own the resource
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	log.Printf("[BOLA READ] User %s accessing user %s", callerID, req.UserId)

	user, ok := store.users[req.UserId]
	if !ok {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// VULNERABLE: Returns user data without ownership check
	return user, nil
}

func (s *userServiceServer) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UserResponse, error) {
	// VULNERABLE: No ownership check
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	log.Printf("[BOLA WRITE] User %s updating user %s", callerID, req.UserId)

	user, ok := store.users[req.UserId]
	if !ok {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// Update fields
	if req.Username != "" {
		user.Username = req.Username
	}
	if req.Email != "" {
		user.Email = req.Email
	}

	return user, nil
}

func (s *userServiceServer) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.Empty, error) {
	// VULNERABLE: No ownership check
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	log.Printf("[BOLA DELETE] User %s deleting user %s", callerID, req.UserId)

	if _, ok := store.users[req.UserId]; !ok {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	delete(store.users, req.UserId)
	return &pb.Empty{}, nil
}

func (s *userServiceServer) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	// VULNERABLE: Returns all users to any authenticated user
	_, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	var users []*pb.UserResponse
	for _, user := range store.users {
		users = append(users, user)
	}

	return &pb.ListUsersResponse{
		Users:      users,
		TotalCount: int32(len(users)),
	}, nil
}

// ProfileServiceServer implementation
type profileServiceServer struct {
	pb.UnimplementedProfileServiceServer
}

func (s *profileServiceServer) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.ProfileResponse, error) {
	// VULNERABLE: No ownership check
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	log.Printf("[SENSITIVE DATA] User %s accessing profile %s (SSN exposed)", callerID, req.UserId)

	profile, ok := store.profiles[req.UserId]
	if !ok {
		return nil, status.Error(codes.NotFound, "profile not found")
	}

	// VULNERABLE: Returns SSN and credit score
	return profile, nil
}

func (s *profileServiceServer) UpdateProfile(ctx context.Context, req *pb.UpdateProfileRequest) (*pb.ProfileResponse, error) {
	// VULNERABLE: No ownership check
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	log.Printf("[BOLA WRITE] User %s updating profile %s", callerID, req.UserId)

	profile, ok := store.profiles[req.UserId]
	if !ok {
		return nil, status.Error(codes.NotFound, "profile not found")
	}

	if req.FullName != "" {
		profile.FullName = req.FullName
	}
	if req.PhoneNumber != "" {
		profile.PhoneNumber = req.PhoneNumber
	}
	if req.Address != "" {
		profile.Address = req.Address
	}

	return profile, nil
}

// AdminServiceServer implementation
type adminServiceServer struct {
	pb.UnimplementedAdminServiceServer
}

func (s *adminServiceServer) GetSystemConfig(ctx context.Context, req *pb.Empty) (*pb.SystemConfigResponse, error) {
	// VULNERABLE: No role check - any authenticated user can access
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	user := store.users[callerID]
	log.Printf("[BFLA] User %s (role: %s) accessing system config", callerID, user.Role)

	// VULNERABLE: Returns database URL and API secret
	return store.config, nil
}

func (s *adminServiceServer) SetSystemConfig(ctx context.Context, req *pb.SystemConfigRequest) (*pb.Empty, error) {
	// VULNERABLE: No role check
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	user := store.users[callerID]
	log.Printf("[BFLA] User %s (role: %s) updating system config", callerID, user.Role)

	store.config.DebugMode = req.DebugMode
	store.config.MaintenanceMode = req.MaintenanceMode
	if len(req.AllowedOrigins) > 0 {
		store.config.AllowedOrigins = req.AllowedOrigins
	}

	return &pb.Empty{}, nil
}

func (s *adminServiceServer) ListAllUsers(ctx context.Context, req *pb.Empty) (*pb.ListUsersResponse, error) {
	// VULNERABLE: No role check
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	user := store.users[callerID]
	log.Printf("[BFLA] User %s (role: %s) listing all users", callerID, user.Role)

	var users []*pb.UserResponse
	for _, user := range store.users {
		users = append(users, user)
	}

	return &pb.ListUsersResponse{
		Users:      users,
		TotalCount: int32(len(users)),
	}, nil
}

func (s *adminServiceServer) DeleteAnyUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.Empty, error) {
	// VULNERABLE: No role check
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	user := store.users[callerID]
	log.Printf("[BFLA] User %s (role: %s) deleting user %s", callerID, user.Role, req.UserId)

	if _, ok := store.users[req.UserId]; !ok {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	delete(store.users, req.UserId)
	return &pb.Empty{}, nil
}

// OrderServiceServer implementation
type orderServiceServer struct {
	pb.UnimplementedOrderServiceServer
}

func (s *orderServiceServer) GetOrder(ctx context.Context, req *pb.GetOrderRequest) (*pb.OrderResponse, error) {
	// VULNERABLE: No ownership check
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	// VULNERABLE: Logs and processes metadata headers
	md, _ := metadata.FromIncomingContext(ctx)
	if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
		log.Printf("[METADATA INJECTION] X-Forwarded-For: %s", xff[0])
	}
	if xri := md.Get("x-real-ip"); len(xri) > 0 {
		log.Printf("[METADATA INJECTION] X-Real-IP: %s", xri[0])
	}

	log.Printf("[BOLA READ] User %s accessing order %s", callerID, req.OrderId)

	order, ok := store.orders[req.OrderId]
	if !ok {
		return nil, status.Error(codes.NotFound, "order not found")
	}

	return order, nil
}

func (s *orderServiceServer) CreateOrder(ctx context.Context, req *pb.CreateOrderRequest) (*pb.OrderResponse, error) {
	callerID, err := getUserIDFromToken(ctx)
	if err != nil {
		return nil, err
	}

	// VULNERABLE: Logs and processes metadata headers
	md, _ := metadata.FromIncomingContext(ctx)
	if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
		log.Printf("[METADATA INJECTION] X-Forwarded-For: %s", xff[0])
	}

	orderID := fmt.Sprintf("%d", len(store.orders)+1)
	order := &pb.OrderResponse{
		Id:          orderID,
		UserId:      callerID,
		ProductId:   req.ProductId,
		Quantity:    req.Quantity,
		TotalAmount: float64(req.Quantity) * 49.99,
		Status:      "pending",
		CreatedAt:   time.Now().Format(time.RFC3339),
	}

	store.orders[orderID] = order
	return order, nil
}

func (s *orderServiceServer) StreamOrders(req *pb.StreamOrdersRequest, stream pb.OrderService_StreamOrdersServer) error {
	// VULNERABLE: Does not respect deadlines, slow streaming
	callerID, err := getUserIDFromToken(stream.Context())
	if err != nil {
		return err
	}

	log.Printf("[DEADLINE] User %s streaming orders (slow, no deadline check)", callerID)

	count := 0
	for _, order := range store.orders {
		// VULNERABLE: Intentionally slow streaming
		time.Sleep(2 * time.Second)

		if err := stream.Send(order); err != nil {
			return err
		}

		count++
		if req.Limit > 0 && int32(count) >= req.Limit {
			break
		}
	}

	return nil
}

func main() {
	host := os.Getenv("GRPC_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("GRPC_PORT")
	if port == "" {
		port = "50051"
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()

	// Register services
	pb.RegisterUserServiceServer(grpcServer, &userServiceServer{})
	pb.RegisterProfileServiceServer(grpcServer, &profileServiceServer{})
	pb.RegisterAdminServiceServer(grpcServer, &adminServiceServer{})
	pb.RegisterOrderServiceServer(grpcServer, &orderServiceServer{})

	// Enable reflection for service discovery
	reflection.Register(grpcServer)

	log.Printf("⚠️  Vulnerable gRPC server starting on %s:%s", host, port)
	log.Printf("⚠️  THIS IS AN INTENTIONALLY VULNERABLE APPLICATION FOR TESTING ONLY")
	log.Printf("⚠️  DO NOT USE IN PRODUCTION")
	log.Println()
	log.Println("Available tokens for testing:")
	log.Println("  admin-token-12345 (user_id: 1, role: admin)")
	log.Println("  user1-token-67890 (user_id: 2, role: user)")
	log.Println("  user2-token-abcde (user_id: 3, role: user)")
	log.Println()

	// Graceful shutdown on interrupt
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("Received %v, shutting down gracefully...", sig)
		grpcServer.GracefulStop()
	}()

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
