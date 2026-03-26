package runner

import (
	"fmt"
	"strings"
)

// ParseCustomHeaders parses CLI header strings ("Key: Value") into a map.
// Returns an error if any header is malformed.
func ParseCustomHeaders(headers []string) (map[string]string, error) {
	result := make(map[string]string, len(headers))
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header format %q: expected 'Key: Value'", h)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("invalid header format %q: empty key", h)
		}
		result[key] = value
	}
	return result, nil
}
