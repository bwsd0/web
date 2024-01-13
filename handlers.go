package main

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

func Index(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		http.NotFound(w, r)
	}
	serveStaticFS(w, r, fsys, r.URL.Path)
	return
}

func serveStaticFS(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	wkf := path.Base(name)
	switch wkf {
	case "robots.txt":
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	case "security.txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	default:
		return
	}

	fs := http.FileServer(http.FS(fsys))
	r.URL.Path = name
	fs.ServeHTTP(w, r)
}
