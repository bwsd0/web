package main

// TODO: implement OCSP stapling for acme/autocert. See: golang.org/issue/51064
// TODO: implement DNS-01 challenges. See: RFC 8555, 8.4

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func NewX509Certificate(dirCache string, selfSign bool) (*tls.Config, error) {
	if !selfSign {
		m, err := autocertX509(dirCache)
		if err != nil {
			return nil, err
		}
		return m.TLSConfig(), nil
	}
	return selfSignedX509(dirCache)
}

func selfSignedX509(dirCache string) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("serial number: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"web"},
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
	}

	return cfg, nil
}

func autocertX509(dirCache string) (*autocert.Manager, error) {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			domain, err := os.Hostname()
			if err != nil {
				return err
			}
			if !strings.HasSuffix(host, "."+domain) && host != domain {
				return fmt.Errorf("domain (%q) disallowed by autocert host policy", host)
			}
			return nil
		},

		Cache:  autocert.DirCache(dirCache),
		Client: new(acme.Client),
	}

	return m, nil
}
