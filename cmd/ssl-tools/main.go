package main

import (
	"log"
	"os"

	"github.com/Hamed0406/ssl-tools/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
