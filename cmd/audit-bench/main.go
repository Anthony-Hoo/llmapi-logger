// Command audit-bench is the A/B load and storage measurement tool of issue
// #59. The logic lives in internal/auditbench; see its help text and
// doc/features/14-test-benchmark-and-fault-injection.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"llmapi-logger/internal/auditbench"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := auditbench.Main(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
