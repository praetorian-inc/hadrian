package runner

import "fmt"

const (
	bannerColorCyan  = "\033[36m"
	bannerColorBold  = "\033[1m"
	bannerColorGray  = "\033[90m"
	bannerColorReset = "\033[0m"
)

// Version can be overridden via ldflags in a future ticket.
var Version = "1.0.0"

const banner = `
 _   _    _    ____  ____  ___    _    _   _
| | | |  / \  |  _ \|  _ \|_ _|  / \  | \ | |
| |_| | / _ \ | | | | |_) || |  / _ \ |  \| |
|  _  |/ ___ \| |_| |  _ < | | / ___ \| |\  |
|_| |_/_/   \_\____/|_| \_\___/_/   \_\_| \_|
`

func printBanner() {
	fmt.Printf("%s%s%s", bannerColorBold, bannerColorCyan, banner)
	fmt.Printf("%s  Praetorian Security — v%s%s\n\n", bannerColorGray, Version, bannerColorReset)
}
