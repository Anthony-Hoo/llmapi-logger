// Package app assembles and runs the audit proxy process.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/proxy"
	"llmapi-logger/internal/routing"
)

const shutdownTimeout = 30 * time.Second

// App owns the stage-one data-plane HTTP server.
type App struct {
	server *http.Server
	logger *slog.Logger
}

// Load reads, validates, and assembles one application from a config file.
func Load(path string, logger *slog.Logger) (*App, error) {
	configuration, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return New(configuration, logger)
}

// ValidateConfig runs all stage-one construction checks without binding a
// listener or contacting NewAPI.
func ValidateConfig(path string) error {
	configuration, err := config.Load(path)
	if err != nil {
		return err
	}
	_, err = New(configuration, slog.New(slog.NewTextHandler(discardWriter{}, nil)))
	return err
}

// New assembles the route matcher, interceptor engine, and reverse proxy.
func New(configuration config.Config, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}

	target, err := url.Parse(configuration.NewAPIURL)
	if err != nil {
		return nil, fmt.Errorf("parse newapi_url: %w", err)
	}
	matcher, err := routing.Compile(configuration.Routes)
	if err != nil {
		return nil, err
	}
	engine, err := interceptor.NewEngine(configuration.Interceptors, configuration.Routes)
	if err != nil {
		return nil, err
	}

	return &App{
		server: &http.Server{
			Addr:              configuration.Listen,
			Handler:           proxy.New(target, matcher, engine, logger),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
		logger: logger,
	}, nil
}

// Run serves until the context is cancelled or the server fails. Cancellation
// initiates a bounded graceful shutdown.
func (application *App) Run(ctx context.Context) error {
	if application == nil || application.server == nil {
		return errors.New("app: nil application")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	listener, err := net.Listen("tcp", application.server.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", application.server.Addr, err)
	}
	application.logger.Info("audit proxy listening", "address", listener.Addr().String())

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- application.server.Serve(listener)
	}()

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve data listener: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := application.server.Shutdown(shutdownContext); err != nil {
			_ = application.server.Close()
			return fmt.Errorf("shutdown data listener: %w", err)
		}
		if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve data listener: %w", err)
		}
		return nil
	}
}

type discardWriter struct{}

func (discardWriter) Write(data []byte) (int, error) {
	return len(data), nil
}
