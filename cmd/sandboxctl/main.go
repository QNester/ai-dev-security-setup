package main

import (
	"context"
	"os"

	"github.com/QNester/ai-dev-security-setup/internal/cli"
)

func main() {
	app := cli.New(os.Stdout, os.Stderr)
	os.Exit(app.Run(context.Background(), os.Args[0], os.Args[1:]))
}
