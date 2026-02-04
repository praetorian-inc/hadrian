// pkg/runner/grpc_helpers.go
package runner

import (
	"fmt"

	"github.com/praetorian-inc/hadrian/pkg/log"
	"google.golang.org/grpc/metadata"
)

// metadataToMap converts gRPC metadata to a string map
// Uses the first value for multi-value headers
func metadataToMap(md metadata.MD) map[string]string {
	m := make(map[string]string)
	for key, values := range md {
		if len(values) > 0 {
			m[key] = values[0]
		}
	}
	return m
}

// mapToMetadata converts a string map to gRPC metadata
func mapToMetadata(m map[string]string) metadata.MD {
	md := metadata.MD{}
	for key, value := range m {
		md.Set(key, value)
	}
	return md
}

// grpcStatusToString converts a gRPC status code to its string name
func grpcStatusToString(code int) string {
	// gRPC status codes: https://grpc.github.io/grpc/core/md_doc_statuscodes.html
	switch code {
	case 0:
		return "OK"
	case 1:
		return "CANCELLED"
	case 2:
		return "UNKNOWN"
	case 3:
		return "INVALID_ARGUMENT"
	case 4:
		return "DEADLINE_EXCEEDED"
	case 5:
		return "NOT_FOUND"
	case 6:
		return "ALREADY_EXISTS"
	case 7:
		return "PERMISSION_DENIED"
	case 8:
		return "RESOURCE_EXHAUSTED"
	case 9:
		return "FAILED_PRECONDITION"
	case 10:
		return "ABORTED"
	case 11:
		return "OUT_OF_RANGE"
	case 12:
		return "UNIMPLEMENTED"
	case 13:
		return "INTERNAL"
	case 14:
		return "UNAVAILABLE"
	case 15:
		return "DATA_LOSS"
	case 16:
		return "UNAUTHENTICATED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", code)
	}
}

// grpcVerboseLog prints message if verbose mode is enabled (gRPC-specific version)
func grpcVerboseLog(verbose bool, format string, args ...interface{}) {
	if verbose {
		log.Debug(format, args...)
	}
}

// grpcDryRunLog prints message if dry run mode is enabled (gRPC-specific version)
func grpcDryRunLog(dryRun bool, format string, args ...interface{}) {
	if dryRun {
		log.Debug("[DRY RUN] "+format, args...)
	}
}
