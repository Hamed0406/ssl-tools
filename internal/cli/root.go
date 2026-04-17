package cli

import (
	"fmt"

	"ssl-tools/internal/app"
	"ssl-tools/internal/version"
)

func Run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "version", "-v", "--version":
		fmt.Println(version.String())
		return nil
	case "check":
		return app.RunCheck(args[1:])
	case "host":
		return app.RunHost(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func printUsage() {
	fmt.Println("ssl-tools")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  ssl-tools <command> [arguments]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  check <file> [--json] [--quiet]     Analyze a certificate file (.pem or .cer)")
	fmt.Println("  host <hostname> [--json] [--quiet] [--servername <name>] [--timeout <duration>] [--proxy <url>]  Check TLS certificate chain from a live host")
	fmt.Println("  version          Print version")
}
