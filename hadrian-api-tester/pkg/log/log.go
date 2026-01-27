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
	ColorBold    = "\033[1m"
)

// Info prints an info message with green [INFO] prefix
func Info(format string, args ...interface{}) {
	fmt.Printf("%s[INFO]%s %s\n", ColorGreen, ColorReset, fmt.Sprintf(format, args...))
}

// Warn prints a warning message with magenta [WARN] prefix
func Warn(format string, args ...interface{}) {
	fmt.Printf("%s[WARN]%s %s\n", ColorMagenta, ColorReset, fmt.Sprintf(format, args...))
}
