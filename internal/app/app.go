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
	"sync/atomic"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/proxy"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/retention"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
	"llmapi-logger/internal/web"
)

const shutdownTimeout = 30 * time.Second

// App owns the stage-one data-plane HTTP server.
type App struct {
	server       *http.Server
	adminServer  *web.Server
	adminAddress string
	parserWorker *parser.Worker
	retention    *retention.Runner
	auditSink    audit.Sink
	auditManager *audit.Manager
	auditStore   *sqlite.Store
	cipher       security.Cipher
	mode         string
	logger       *slog.Logger

	parserHealthy atomic.Bool
	closeOnce     sync.Once
	closeErr      error
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
	_, _, _, _, err = assembleDataPlane(configuration)
	return err
}

// New assembles the route matcher, interceptor engine, and reverse proxy.
func New(configuration config.Config, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}

	target, upstreamProxy, matcher, engine, err := assembleDataPlane(configuration)
	if err != nil {
		return nil, err
	}

	runtime := assembleAudit(configuration, logger)
	application := &App{
		server: &http.Server{
			Addr: configuration.Listen,
			Handler: proxy.NewWithOptions(target, matcher, engine, proxy.Options{
				Audit:         runtime.sink,
				UpstreamProxy: upstreamProxy,
			}, logger),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
		adminAddress: configuration.AdminListen,
		auditSink:    runtime.sink,
		auditManager: runtime.manager,
		auditStore:   runtime.store,
		cipher:       runtime.cipher,
		mode:         configuration.Mode,
		logger:       logger,
	}

	var queryService *query.Service
	if runtime.store != nil && runtime.cipher != nil {
		queryService, err = query.New(runtime.store, runtime.cipher)
		if err != nil {
			_ = runtime.store.Close()
			return nil, fmt.Errorf("assemble query service: %w", err)
		}
		application.parserWorker, err = parser.NewWorker(runtime.store, runtime.cipher, builtin.All(), logger)
		if err != nil {
			_ = runtime.store.Close()
			return nil, fmt.Errorf("assemble parser worker: %w", err)
		}
		if runtime.manager != nil {
			runtime.manager.SetCompletionNotifier(application.parserWorker.Notify)
		}
	}
	if runtime.store != nil && configuration.RetentionDays > 0 {
		application.retention, err = retention.New(runtime.store, configuration.RetentionDays, logger)
		if err != nil {
			_ = application.closeComponents()
			return nil, fmt.Errorf("assemble retention runner: %w", err)
		}
	}

	application.adminServer, err = web.NewServer(configuration.AdminListen, web.Options{
		AdminToken: configuration.AdminToken,
		Query:      queryService,
		Assets:     web.EmbeddedAssets(),
		Readiness:  application.readiness,
		Logger:     logger,
	})
	if err != nil {
		_ = application.closeComponents()
		return nil, fmt.Errorf("assemble admin server: %w", err)
	}
	return application, nil
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
	defer application.closeComponents()
	if application.auditManager != nil {
		application.auditManager.StartGapFlusher(ctx)
	}
	if application.retention != nil {
		application.retention.Start(ctx)
	}

	if application.parserWorker != nil {
		if err := application.parserWorker.Start(ctx); err != nil {
			application.logger.Warn("parser worker unavailable", "error_category", "parser_start_failed")
		} else {
			application.parserHealthy.Store(true)
		}
	}

	dataListener, err := net.Listen("tcp", application.server.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", application.server.Addr, err)
	}
	adminListener, err := net.Listen("tcp", application.adminAddress)
	if err != nil {
		_ = dataListener.Close()
		return fmt.Errorf("listen on admin %s: %w", application.adminAddress, err)
	}
	application.logger.Info("audit proxy listening", "address", dataListener.Addr().String())
	application.logger.Info("audit admin listening", "address", adminListener.Addr().String())

	type serveResult struct {
		name string
		err  error
	}
	serveResults := make(chan serveResult, 2)
	go func() {
		serveResults <- serveResult{name: "data", err: application.server.Serve(dataListener)}
	}()
	go func() {
		serveResults <- serveResult{name: "admin", err: application.adminServer.Serve(adminListener)}
	}()

	received := 0
	var runErr error
	select {
	case result := <-serveResults:
		received++
		if result.err != nil && !errors.Is(result.err, http.ErrServerClosed) {
			runErr = fmt.Errorf("serve %s listener: %w", result.name, result.err)
		}
	case <-ctx.Done():
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	shutdownErr := errors.Join(
		application.server.Shutdown(shutdownContext),
		application.adminServer.Shutdown(shutdownContext),
	)
	cancel()
	if shutdownErr != nil {
		_ = application.server.Close()
		_ = application.adminServer.Close()
	}

	for received < 2 {
		result := <-serveResults
		received++
		if result.err != nil && !errors.Is(result.err, http.ErrServerClosed) {
			runErr = errors.Join(runErr, fmt.Errorf("serve %s listener: %w", result.name, result.err))
		}
	}
	if shutdownErr != nil {
		runErr = errors.Join(runErr, fmt.Errorf("shutdown listeners: %w", shutdownErr))
	}
	return runErr
}

// Close releases the audit store for callers that assemble an App without
// entering Run, such as tests and embedding processes.
func (application *App) Close() error {
	if application == nil {
		return nil
	}
	return application.closeComponents()
}

func (application *App) closeComponents() error {
	application.closeOnce.Do(func() {
		if application.retention != nil {
			application.retention.Close()
		}
		if application.parserWorker != nil {
			application.parserWorker.Close()
			application.parserHealthy.Store(false)
		}
		if application.auditManager != nil {
			flushContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			application.auditManager.CloseGaps(flushContext)
			cancel()
		}
		if application.auditStore != nil {
			application.closeErr = application.auditStore.Close()
		}
	})
	return application.closeErr
}

func (application *App) readiness(context.Context) web.ReadyStatus {
	status := web.ReadyStatus{
		Status:        "healthy",
		Database:      "ok",
		EncryptionKey: "ok",
	}
	if application.parserWorker != nil {
		status.ParserQueue = application.parserWorker.QueueLength()
	}

	auditHealthy := application.auditSink != nil && application.auditSink.Healthy()
	if application.auditStore == nil || !application.auditStore.Healthy() {
		status.Database = "unavailable"
		auditHealthy = false
	}
	if application.cipher == nil {
		status.EncryptionKey = "unavailable"
		auditHealthy = false
	}
	if !auditHealthy {
		if application.mode == audit.ModeStrict {
			status.Status = "not_ready"
		} else {
			status.Status = "degraded"
		}
		return status
	}
	if application.parserWorker != nil && !application.parserHealthy.Load() {
		status.Status = "degraded"
	}
	return status
}

func assembleDataPlane(configuration config.Config) (*url.URL, *url.URL, *routing.Matcher, *interceptor.Engine, error) {
	target, err := url.Parse(configuration.NewAPIURL)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse newapi_url: %w", err)
	}
	var upstreamProxy *url.URL
	if configuration.NewAPIProxyURL != "" {
		upstreamProxy, err = url.Parse(configuration.NewAPIProxyURL)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("parse newapi_proxy_url: %w", err)
		}
	}
	matcher, err := routing.Compile(configuration.Routes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	engine, err := interceptor.NewEngine(configuration.Interceptors, configuration.Routes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return target, upstreamProxy, matcher, engine, nil
}

type auditRuntime struct {
	sink    audit.Sink
	manager *audit.Manager
	store   *sqlite.Store
	cipher  security.Cipher
}

func assembleAudit(configuration config.Config, logger *slog.Logger) auditRuntime {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store, err := sqlite.Open(ctx, configuration.DBPath)
	if err != nil {
		logger.Warn("audit storage unavailable", "mode", configuration.Mode, "error_category", "db_unavailable")
		manager := audit.NewUnavailable(configuration.Mode, err, logger)
		return auditRuntime{sink: manager, manager: manager}
	}
	hasAudits, err := store.HasAudits(ctx)
	if err != nil {
		_ = store.Close()
		logger.Warn("audit storage unavailable", "mode", configuration.Mode, "error_category", "db_unavailable")
		manager := audit.NewUnavailable(configuration.Mode, err, logger)
		return auditRuntime{sink: manager, manager: manager}
	}
	recovered, recoveryErr := store.RecoverInterruptedAudits(ctx, time.Now().UnixNano())
	if recoveryErr != nil {
		_ = store.Close()
		logger.Warn("interrupted audit recovery failed", "error_category", "recovery_failed")
		manager := audit.NewUnavailable(configuration.Mode, recoveryErr, logger)
		return auditRuntime{sink: manager, manager: manager}
	} else if recovered > 0 {
		logger.Info("interrupted audits recovered", "recovered_audits", recovered)
	}
	key, err := security.LoadOrCreateKey(configuration.KeyPath, !hasAudits)
	if err != nil {
		_ = store.Close()
		logger.Warn("audit key unavailable", "mode", configuration.Mode, "error_category", "key_unavailable")
		manager := audit.NewUnavailable(configuration.Mode, err, logger)
		return auditRuntime{sink: manager, manager: manager}
	}
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		_ = store.Close()
		logger.Warn("audit cipher unavailable", "mode", configuration.Mode, "error_category", "key_unavailable")
		manager := audit.NewUnavailable(configuration.Mode, err, logger)
		return auditRuntime{sink: manager, manager: manager}
	}
	manager, err := audit.NewManager(store, cipher, configuration.Mode, logger)
	if err != nil {
		_ = store.Close()
		logger.Warn("audit manager unavailable", "mode", configuration.Mode, "error_category", "audit_unavailable")
		unavailable := audit.NewUnavailable(configuration.Mode, err, logger)
		return auditRuntime{sink: unavailable, manager: unavailable}
	}
	return auditRuntime{sink: manager, manager: manager, store: store, cipher: cipher}
}

type discardWriter struct{}

func (discardWriter) Write(data []byte) (int, error) {
	return len(data), nil
}
