// Command skill-trust signs and verifies AI agent skills with Sigstore.
package main

import (
	"os"

	"github.com/redhat-et/skill-trust/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
