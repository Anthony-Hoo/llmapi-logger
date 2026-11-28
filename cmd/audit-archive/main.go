// Command audit-archive is the stand-alone reader of the cold archive: it
// lists, verifies, prints and exports archived audits from the archive
// directory alone, without a database. All logic lives in
// internal/archivecli; run "audit-archive --help".
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"llmapi-logger/internal/archivecli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := archivecli.Main(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
