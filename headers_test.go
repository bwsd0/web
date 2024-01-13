package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecHeaders(t *testing.T) {
	shm := SecureHeaders()
	ts := httptest.NewUnstartedServer(shm(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {})),
	)
	ts.StartTLS()
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Errorf("%v", err)
	}
	defer resp.Body.Close()

	headers := []string{
		"content-security-policy",
		"x-content-type-options",
		"referrer-policy",
		"permissions-policy",
	}

	for _, hdr := range headers {
		if got := resp.Header.Get(hdr); got == "" {
			t.Errorf("expected non-empty value for header: %q", hdr)
		}
	}
}
