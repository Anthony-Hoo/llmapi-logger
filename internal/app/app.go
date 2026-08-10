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
	"sync"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/proxy"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

const shutdownTimeout = 30 * time.Second

// App owns the stage-one data-plane HTTP server.
type App struct {
	server     *http.Server
	logger     *slog.Logger
	auditStore *sqlite.Store
	closeOnce  sync.Once
	closeErr   error
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
	_, _, _, err = assembleDataPlane(configuration)
	return err
}

// New assembles the route matcher, interceptor engine, and reverse proxy.
func New(configuration config.Config, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}

	target, matcher, engine, err := assembleDataPlane(configuration)
	if err != nil {
		return nil, err
	}

	auditSink, auditStore := assembleAudit(configuration, logger)

	return &App{
		server: &http.Server{
			Addr:              configuration.Listen,
			Handler:           proxy.NewWithAudit(target, matcher, engine, auditSink, logger),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
		logger:     logger,
		auditStore: auditStore,
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
	defer application.closeAuditStore()

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

// Close releases the audit store for callers that assemble an App without
// entering Run, such as tests and embedding processes.
func (application *App) Close() error {
	if application == nil {
		return nil
	}
	return application.closeAuditStore()
}

func (application *App) closeAuditStore() error {
	application.closeOnce.Do(func() {
		if application.auditStore != nil {
			application.closeErr = application.auditStore.Close()
		}
	})
	return application.closeErr
}

func assembleDataPlane(configuration config.Config) (*url.URL, *routing.Matcher, *interceptor.Engine, error) {
	target, err := url.Parse(configuration.NewAPIURL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse newapi_url: %w", err)
	}
	matcher, err := routing.Compile(configuration.Routes)
	if err != nil {
		return nil, nil, nil, err
	}
	engine, err := interceptor.NewEngine(configuration.Interceptors, configuration.Routes)
	if err != nil {
		return nil, nil, nil, err
	}
	return target, matcher, engine, nil
}

func assembleAudit(configuration config.Config, logger *slog.Logger) (audit.Sink, *sqlite.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store, err := sqlite.Open(ctx, configuration.DBPath)
	if err != nil {
		logger.Warn("audit storage unavailable", "mode", configuration.Mode, "error_category", "db_unavailable")
		return audit.NewUnavailable(configuration.Mode, err, logger), nil
	}
	hasAudits, err := store.HasAudits(ctx)
	if err != nil {
		_ = store.Close()
		logger.Warn("audit storage unavailable", "mode", configuration.Mode, "error_category", "db_unavailable")
		return audit.NewUnavailable(configuration.Mode, err, logger), nil
	}
	key, err := security.LoadOrCreateKey(configuration.KeyPath, !hasAudits)
	if err != nil {
		_ = store.Close()
		logger.Warn("audit key unavailable", "mode", configuration.Mode, "error_category", "key_unavailable")
		return audit.NewUnavailable(configuration.Mode, err, logger), nil
	}
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		_ = store.Close()
		logger.Warn("audit cipher unavailable", "mode", configuration.Mode, "error_category", "key_unavailable")
		return audit.NewUnavailable(configuration.Mode, err, logger), nil
	}
	manager, err := audit.NewManager(store, cipher, configuration.Mode, logger)
	if err != nil {
		_ = store.Close()
		logger.Warn("audit manager unavailable", "mode", configuration.Mode, "error_category", "audit_unavailable")
		return audit.NewUnavailable(configuration.Mode, err, logger), nil
	}
	return manager, store
}

type discardWriter struct{}

func (discardWriter) Write(data []byte) (int, error) {
	return len(data), nil
}
