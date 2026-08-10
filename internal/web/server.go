package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// Server is the independently managed admin listener used by app assembly.
type Server struct {
	http *http.Server
}

func NewServer(address string, options Options) (*Server, error) {
	if address == "" {
		return nil, errors.New("web: empty listen address")
	}
	handler, err := NewHandler(options)
	if err != nil {
		return nil, err
	}
	return &Server{http: &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}}, nil
}

func (server *Server) ListenAndServe() error {
	if server == nil || server.http == nil {
		return errors.New("web: nil server")
	}
	return server.http.ListenAndServe()
}

// Serve runs the management HTTP server on a listener already bound by the
// application, allowing the data and admin listeners to start atomically.
func (server *Server) Serve(listener net.Listener) error {
	if server == nil || server.http == nil {
		return errors.New("web: nil server")
	}
	if listener == nil {
		return errors.New("web: nil listener")
	}
	return server.http.Serve(listener)
}

func (server *Server) Shutdown(ctx context.Context) error {
	if server == nil || server.http == nil {
		return nil
	}
	return server.http.Shutdown(ctx)
}

func (server *Server) Close() error {
	if server == nil || server.http == nil {
		return nil
	}
	return server.http.Close()
}

func (server *Server) Handler() http.Handler {
	if server == nil || server.http == nil {
		return nil
	}
	return server.http.Handler
}
