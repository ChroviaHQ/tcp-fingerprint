package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unicode/utf8"
)

type capturedConn struct {
	net.Conn
	result Result
}
type captureListener struct{ net.Listener }

func (l captureListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	b, err := savedSYN(c)
	if err != nil {
		log.Printf("SYN capture failed for %s: %v", c.RemoteAddr(), err)
	}
	r := resultForSYN(b, err)
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	r.ExitIP = host
	return &capturedConn{Conn: c, result: r}, nil
}

type resultKey struct{}

func connectionContext(ctx context.Context, c net.Conn) context.Context {
	if cc, ok := c.(*capturedConn); ok {
		return context.WithValue(ctx, resultKey{}, cc.result)
	}
	return ctx
}
func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /detect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "invalid query", http.StatusBadRequest)
			return
		}
		id := query.Get("test_id")
		if !utf8.ValidString(id) {
			http.Error(w, "test_id must be valid UTF-8", http.StatusBadRequest)
			return
		}
		if len(id) > 128 {
			http.Error(w, "test_id exceeds 128 bytes", http.StatusBadRequest)
			return
		}
		result, ok := r.Context().Value(resultKey{}).(Result)
		if !ok {
			http.Error(w, "connection fingerprint unavailable", http.StatusServiceUnavailable)
			return
		}
		result.TestID = id
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			log.Printf("response write failed: %v", err)
		}
	})
	return mux
}
func run() error {
	addr := flag.String("listen", ":38473", "listen address")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ln, err := listenTCP(ctx, *addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	server := &http.Server{Handler: handler(), ConnContext: connectionContext, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
		}
	}()
	log.Printf("HTTP listening on %s", ln.Addr())
	err = server.Serve(captureListener{ln})
	stop()
	<-done
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
