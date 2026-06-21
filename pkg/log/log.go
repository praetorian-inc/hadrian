package log

import (
	"fmt"
	"os"
	"sync/atomic"
)

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

// verboseFlag controls whether operational messages (Debug) are displayed.
// Security findings are always displayed via the reporter system regardless of this setting.
// Warnings are always displayed regardless of verbose mode.
var verboseFlag atomic.Bool

// SetVerbose enables or disables verbose output for operational messages.
func SetVerbose(v bool) {
	verboseFlag.Store(v)
}

// IsVerbose returns the current verbose setting.
func IsVerbose() bool {
	return verboseFlag.Load()
}

// Info prints an informational message to stderr (always displayed)
func Info(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s[INFO]%s %s\n", ColorCyan, ColorReset, fmt.Sprintf(format, args...))
}

// Warn prints a warning message with magenta [WARN] prefix to stderr (always displayed)
func Warn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s[WARN]%s %s\n", ColorMagenta, ColorReset, fmt.Sprintf(format, args...))
}

// Error prints an error message with red [ERROR] prefix to stderr (always displayed)
func Error(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s[ERROR]%s %s\n", ColorRed, ColorReset, fmt.Sprintf(format, args...))
}

// Debug prints a debug message with cyan [DEBUG] prefix (only if verbose mode is enabled)
func Debug(format string, args ...interface{}) {
	if !verboseFlag.Load() {
		return
	}
	fmt.Printf("%s[DEBUG]%s %s\n", ColorCyan, ColorReset, fmt.Sprintf(format, args...))
}
