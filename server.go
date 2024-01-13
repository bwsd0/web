package main

import (
	"crypto/tls"
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

// go:embed all:static
var fsys embed.FS

func ListenAndServe(mux *http.ServeMux, addr, dirCache string, selfSign bool) error {
	var err error
	var cfg *tls.Config
	errc := make(chan error, 3)

	if !selfSign {
		m, err := autocertX509(dirCache)
		if err != nil {
			log.Fatal(err)
		}
		cfg = m.TLSConfig()
		go func() {
			errc <- http.ListenAndServe(":80", m.HTTPHandler(nil))
		}()
	} else {
		if cfg, err = selfSignedX509(dirCache); err != nil {
			log.Fatal(err)
		}
	}

	cfg.MinVersion = tls.VersionTLS13
	s := &http.Server{
		Addr:           addr,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    60 * time.Second,
		Handler:        middleware(mux),
		TLSConfig:      cfg,
		ErrorLog:       logger,
		MaxHeaderBytes: (http.DefaultMaxHeaderBytes >> 8),
	}

	defer s.Close()
	log.Printf("listen: %s", addr)
	go func() { errc <- s.ListenAndServeTLS("", "") }()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		sig := <-ch
		log.Printf("signal %v received; shutting down", sig)
		os.Exit(0)
	}()

	return <-errc
}

func Server(addr, dirCache string, selfSign bool) {
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(Index))

	errc := make(chan error)
	err := ListenAndServe(mux, addr, dirCache, selfSign)

	errc <- fmt.Errorf("ListenAndServe: %v", err)
}
