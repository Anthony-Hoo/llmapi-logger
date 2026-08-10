package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"llmapi-logger/internal/app"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("audit-proxy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to the YAML configuration file")
	validateOnly := flags.Bool("validate-config", false, "validate configuration and exit")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "audit-proxy: unexpected positional arguments")
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "audit-proxy: --config is required")
		return 2
	}

	if *validateOnly {
		if err := app.ValidateConfig(*configPath); err != nil {
			fmt.Fprintf(stderr, "audit-proxy: configuration invalid: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "configuration valid")
		return 0
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	application, err := app.Load(*configPath, logger)
	if err != nil {
		logger.Error("application setup failed", "error", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := application.Run(ctx); err != nil {
		logger.Error("application stopped with error", "error", err)
		return 1
	}
	return 0
}
