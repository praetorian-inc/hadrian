package runner

import "fmt"

const (
	bannerColorRed   = "\033[31m"
	bannerColorBold  = "\033[1m"
	bannerColorGray  = "\033[90m"
	bannerColorReset = "\033[0m"
)

// Version can be overridden via ldflags in a future ticket.
var Version = "1.0.0"

const banner = `
    __  _____    ____  ____  _______    _   __
   / / / /   |  / __ \/ __ \/  _/   |  / | / /
  / /_/ / /| | / / / / /_/ // // /| | /  |/ /
 / __  / ___ |/ /_/ / _, _// // ___ |/ /|  /
/_/ /_/_/  |_/_____/_/ |_/___/_/  |_/_/ |_/

 Praetorian Security, Inc.
`

func printBanner() {
	fmt.Printf("%s%s%s%s\n", bannerColorBold, bannerColorRed, banner, bannerColorReset)
	fmt.Printf("%s  v%s%s\n\n", bannerColorGray, Version, bannerColorReset)
}
