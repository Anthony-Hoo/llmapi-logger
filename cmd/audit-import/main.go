// audit-import is deliberately separate from the runtime startup path.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/migrate"
	"os"
	"os/signal"
	"syscall"
)

func main() { os.Exit(run()) }
func run() int {
	source := flag.String("source", "", "offline schema-12 SQLite database (keep .db, -wal and -shm together)")
	keyPath := flag.String("key-file", "", "existing raw 32-byte audit key; never generated")
	stopped := flag.Bool("service-stopped", false, "confirm old SQLite service and target PostgreSQL service are stopped; back up first")
	dry := flag.Bool("dry-run", false, "validate the full import then roll back all destination changes")
	flag.Parse()
	// DSN comes from an environment variable rather than process arguments.
	key, err := security.LoadOrCreateKey(*keyPath, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit-import: key_load_failed")
		return 1
	}
	defer clear(key)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	report, err := migrate.Run(ctx, migrate.Options{SourcePath: *source, DatabaseURL: os.Getenv("AUDIT_IMPORT_DATABASE_URL"), Key: key, ServiceStopped: *stopped, DryRun: *dry})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return 1
	}
	return 0
}
