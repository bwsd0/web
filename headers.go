package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

const (
	cspNone  = "'none'"
	cspSelf  = "'self'"
	cspBlock = "'block'"
	cspAllow = "'allow'"
)

var csp = map[string][]string{
	"default-src":     {cspNone},
	"base-uri":        {cspNone},
	"font-src":        {cspSelf},
	"form-action":     {cspNone},
	"frame-ancestors": {cspNone},
	"img-src":         {cspSelf},
	"style-src":       {cspSelf},
}

// DefaultCSP is the Content Security Policy (CSP) used by SecureHeaders. This
// version 3 CSP policy begins with "default-src 'none'" (deny all), and then
// incrementally appended with only those policy directives needed for site
// functionionality.
var DefaultCSP = "default-src 'none';"

func init() {
	var c []string
	for k := range csp {
		c = append(c, fmt.Sprintf("%s %s", k, strings.Join(csp[k], " ")))
	}
	sort.Strings(c)
	DefaultCSP = strings.Join(c, ";")
}

var hostList = map[string]bool{
	"blog.bwsd.net": true,
	"bwsd.net":      true,
	"www.bwsd.net":  true,
}

// SecureHeaders returns a handler with security options and policies appended to
// response headers.
func SecureHeaders() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var host string
			host = strings.ToLower(r.Host)
			if ok := hostList[host]; !ok {
				host = "bwsd.net"
			}
			if r.TLS == nil || r.URL.Scheme == "http" {
				r.URL.Scheme = "https"
				http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
				return
			}

			// TLDs pre-registered on the HSTS preload list can omit this header.
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

			w.Header().Set("Content-Security-Policy", DefaultCSP)

			// Obsoleted by CSP frame-ancesors directive.
			w.Header().Set("X-Frame-Options", "Deny")

			// Opt out of Google's FloC cohort calculations
			w.Header().Set("Permissions-Policy", "interest-cohort=()")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "same-origin")

			h.ServeHTTP(w, r)
		})
	}
}

const maxURILen = 512

var DefaultAllowedMethods = []string{"GET", "HEAD", "OPTIONS"}

// AcceptHeaders returns a handler with a list of acceptable methods, returning
// a HTTP 4xx error response when request method is disallowed or exceeds length
// restrictions.
func AcceptHeaders(m ...string) Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var status int

			if len(r.URL.String()) >= maxURILen {
				status = http.StatusRequestURITooLong
				http.Error(w, http.StatusText(http.StatusRequestURITooLong), status)
				return
			}

			if len(m) == 0 {
				m = DefaultAllowedMethods
			}

			for _, am := range DefaultAllowedMethods {
				if r.Method == am {
					h.ServeHTTP(w, r)
					return
				}
			}

			status = http.StatusMethodNotAllowed
			http.Error(w, http.StatusText(status), status)
		})
	}
}
