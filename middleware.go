package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"time"
)

var (
	Default = Apply(Log, Recover)
	logger  = log.New(os.Stdout, "site: ", 0)
)

type Middleware func(http.Handler) http.Handler

// Apply returns a Middleware that applies a sequence of Middlewares to an http
// request.
//
// Middlewares are executed in succession, in the order given as arguments to
// Apply. For example:
//
// Apply(m1, m2,...,mn)(handler) <=> m1(m2(...mn,(handler)))
func Apply(m ...Middleware) Middleware {
	return func(h http.Handler) http.Handler {
		for i := range m {
			h = m[len(m)-1-i](h)
		}
		return h
	}
}

func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				logger.Printf("panic(%): %v\n", err, r.Context())
				fmt.Println(string(debug.Stack()))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// UUID is a universally unique identifier as defined in RFC 4122.
type UUID [16]byte

var rander = rand.Reader

func NewV4UUIDRandom() (UUID, error) {
	return NewV4UUID(rander)
}

func NewV4UUID(r io.Reader) (UUID, error) {
	var u UUID
	_, err := io.ReadFull(r, u[:])
	if err != nil {
		return u, err
	}
	u[6] = (u[6] & 0x0f) | 0x40 // RFC 4122, 4.1.3
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122, 4.1.1
	return u, nil
}

func (uuid UUID) String() string {
	var buf [36]byte
	hex.Encode(buf[:], uuid[:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], uuid[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], uuid[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], uuid[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], uuid[10:])

	return string(buf[:])
}

func NewRequestContext(r *http.Request) context.Context {
	var uuid UUID
	var err error
	if rid := r.Header.Get("uuid"); rid == "" {
		if uuid, err = NewV4UUIDRandom(); err != nil {
			logger.Printf("UUID: %v\n", err)
		}
	}
	return context.WithValue(r.Context(), "uuid", uuid)
}

type CLFEntry struct {
	addr     string    // Client network address
	userID   string    // User ID
	ident    string    // RFC 1413 client identity
	ts       time.Time // Timestamp of the start of the request
	method   string    // Request method
	path     string    //
	proto    string    // Protocol
	status   int       // Status code
	size     int       // Size (in bytes) returned to the client
	ua       string    // Client user agent
	referrer string    // Referrer header (spelt correctly)
}

// NewCLFEntry returns a structure representing a signle combined log format
// entry.
//
// This implementation uses version 4 UUIDs instead of RFC 1413 client
// identities as the latter is seldom used.
func NewCLFEntry(r *http.Request, uuid UUID) *CLFEntry {
	l := &CLFEntry{
		addr:     "-",
		userID:   "-",
		ident:    uuid.String(),
		ts:       time.Now(),
		method:   r.Method,
		path:     r.URL.Path,
		proto:    r.Proto,
		status:   0,
		size:     0,
		ua:       "-",
		referrer: "-",
	}

	if r.UserAgent() != "" {
		l.ua = r.UserAgent()
	}
	if r.Referer() != "" {
		l.referrer = r.Referer()
	}
	if u, _, ok := r.BasicAuth(); ok {
		l.userID = u
	}
	if addr, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		l.addr = addr
	}

	return l
}

const (
	// CommonLogFormat (CLF) is a predefined format for HTTP access logging.
	// CommonLogFormat = `%v %s %s [%v] "%s %s %s" %v %v`

	// CombinedLogFormat is the same as CommonLogFormat with the addition of the
	// HTTP referrer and user agent fields.
	CombinedLogFormat = `%v %s %s [%v] %s %s %v %v "%s" "%s"`
)

// String returns a string representation of CLFLogEntry in Combined Log Format.
func (c *CLFEntry) String() string {
	status := func(code int) string {
		if http.StatusText(code) == "" {
			return "-"
		}
		return fmt.Sprintf("%d", code)
	}

	return fmt.Sprintf(CombinedLogFormat,
		c.addr,
		c.userID,
		c.ident,
		c.ts.Format("02/Jan/2006:15:04:05 -0700"),
		fmt.Sprintf("\"%s %s\"", c.method, c.path),
		c.proto,
		status(c.status),
		c.size,
		c.ua,
		c.referrer,
	)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}

// Log is a middleware that logs the start and end of a request in CLF format.
// Log should be used before other middlewares when used with Apply.
func Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := NewRequestContext(r)
		uuid, ok := ctx.Value("uuid").(UUID)
		if !ok {
			logger.Println("malformed uuid in request context")
		}
		wr := &statusRecorder{w, 200, 0}
		l := NewCLFEntry(r, uuid)
		next.ServeHTTP(wr, r.WithContext(ctx))

		t1 := time.Now()
		l.status = wr.status
		l.size = wr.size
		logger.Println(l)

		// Server response times should generally be <200ms
		took := t1.Sub(l.ts)
		if took/1000 >= 200 {
			logger.Printf("slow request: %x (took: %v)\n", uuid, took)
		}
	})
}

func middleware(mux *http.ServeMux) http.Handler {
	mw := Apply(
		SecureHeaders(),
		AcceptHeaders(),
	)
	return mw(mux)
}
