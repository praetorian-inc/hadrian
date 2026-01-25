package matchers

import (
	"net/http"
	"strings"
)

// buildHeaders constructs a string representation of HTTP headers
func buildHeaders(response *http.Response) string {
	var headers string
	for key, values := range response.Header {
		headers += key + ": " + strings.Join(values, ", ") + "\n"
	}
	return headers
}
