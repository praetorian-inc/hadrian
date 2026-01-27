package log

import "fmt"

// Terminal color codes (exported for reuse across packages)
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorYellow  = "\033[33m"
	ColorGreen   = "\033[32m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorBold    = "\033[1m"
)

// verbose controls whether operational messages (Warn, Debug) are displayed.
// Security findings are always displayed via the reporter system regardless of this setting.
var verbose bool

// SetVerbose enables or disables verbose output for operational messages.
func SetVerbose(v bool) {
	verbose = v
}

// IsVerbose returns the current verbose setting.
func IsVerbose() bool {
	return verbose
}

// Warn prints a warning message with magenta [WARN] prefix (only if verbose mode is enabled)
func Warn(format string, args ...interface{}) {
	if !verbose {
		return
	}
	fmt.Printf("%s[WARN]%s %s\n", ColorMagenta, ColorReset, fmt.Sprintf(format, args...))
}

// Debug prints a debug message with cyan [DEBUG] prefix (only if verbose mode is enabled)
func Debug(format string, args ...interface{}) {
	if !verbose {
		return
	}
	fmt.Printf("%s[DEBUG]%s %s\n", ColorCyan, ColorReset, fmt.Sprintf(format, args...))
}
