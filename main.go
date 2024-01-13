// site serves a static filesystem from the current working directory.
package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	addr     = flag.String("addr", ":4433", "listen address")
	selfSign = flag.Bool("s", true, "self-sign X509 certificate")
	dirCache = flag.String("c", "/etc/ssl/private", "X509 certificate cache")
)

const usageLine = `usage: site [-addr addr] [-s] [-c certdir] domain
options:
`

func usage() {
	fmt.Fprintf(os.Stderr, "%s", usageLine)
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Parse()
	if *dirCache == "" {
		usage()
	}

	if port := os.Getenv("PORT"); port != "" {
		*addr = ":" + port
	}
	Server(*addr, *dirCache, *selfSign)
}
