// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// testCertificate returns a self-signed server certificate for "cotp.test"
// and a pool that trusts it. Its validity covers the clock of a synctest
// bubble, which starts in 2000.
func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cotp.test"},
		DNSNames:              []string{"cotp.test"},
		NotBefore:             time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}

// tlsPair completes a TLS 1.3 handshake over net.Pipe, then Connect and
// Accept over the two *tls.Conn, and returns the client and server Conn.
// Call it inside a synctest bubble; the caller closes both.
func tlsPair(t *testing.T, cert tls.Certificate, roots *x509.CertPool) (client, server *Conn) {
	t.Helper()
	cliRaw, srvRaw := net.Pipe()
	cliTLS := tls.Client(cliRaw, &tls.Config{RootCAs: roots, ServerName: "cotp.test", MinVersion: tls.VersionTLS13})
	srvTLS := tls.Server(srvRaw, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// No ticket after the handshake: net.Pipe has no buffer, and a
		// ticket nobody reads would block the server.
		SessionTicketsDisabled: true,
	})
	handshake := make(chan error, 1)
	go func() { handshake <- srvTLS.Handshake() }()
	if err := cliTLS.Handshake(); err != nil {
		t.Fatalf("TLS handshake, client: %v", err)
	}
	if err := <-handshake; err != nil {
		t.Fatalf("TLS handshake, server: %v", err)
	}

	accepted := make(chan *Conn, 1)
	go func() {
		srv, err := Accept(context.Background(), srvTLS, ServerConfig{})
		if err != nil {
			t.Errorf("Accept: %v", err)
		}
		accepted <- srv
	}()
	cli, err := Connect(context.Background(), cliTLS, ClientConfig{})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	srv := <-accepted
	if srv == nil {
		t.FailNow()
	}
	return cli, srv
}

// Over a *tls.Conn, a WriteTSDU that its context ends while it writes to the
// stream ends the connection, also when the stream accepted no octet:
// crypto/tls fails every write after one that timed out
// (tls.Conn.SetWriteDeadline), so the next write could not succeed. The
// error matches ErrClosed and the context error, every later call and Close
// return it, and the stream is closed.
func TestTSDU_WriteTimeoutOverTLSEndsConnection(t *testing.T) {
	cert, roots := testCertificate(t)
	cases := []struct {
		name  string
		want  error
		write func(conn *Conn) error
	}{
		{"deadline", context.DeadlineExceeded, func(conn *Conn) error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			return conn.WriteTSDU(ctx, []byte{1, 2, 3})
		}},
		{"cancelled", context.Canceled, func(conn *Conn) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- conn.WriteTSDU(ctx, []byte{1, 2, 3}) }()
			synctest.Wait() // the write is blocked: the peer does not read
			cancel()
			return <-done
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cli, srv := tlsPair(t, cert, roots)
				defer func() { _ = srv.Close() }()

				// The server does not read: no octet of the TSDU reaches it.
				before, _ := cli.writeProgress()
				err := tc.write(cli)
				if !errors.Is(err, ErrClosed) || !errors.Is(err, tc.want) {
					t.Fatalf("WriteTSDU = %v, want ErrClosed and %v", err, tc.want)
				}
				if after, _ := cli.writeProgress(); after != before {
					t.Fatalf("%d octets counted, want none: this is the case of a write that moved nothing", after-before)
				}
				if cli.terminalKind() != terminalAborted {
					t.Fatalf("terminal kind %v, want aborted", cli.terminalKind())
				}

				terminal := func(what string, err error) {
					t.Helper()
					if !errors.Is(err, ErrClosed) || !errors.Is(err, tc.want) {
						t.Fatalf("%s = %v, want the terminal error (ErrClosed and %v)", what, err, tc.want)
					}
				}
				terminal("next WriteTSDU", cli.WriteTSDU(context.Background(), []byte{4}))
				_, err = cli.ReadTSDU(context.Background())
				terminal("next ReadTSDU", err)
				terminal("Close", cli.Close())

				// The abort closed the stream: the server sees the end of it.
				if _, err := srv.ReadTSDU(context.Background()); !errors.Is(err, ErrDisconnected) {
					t.Fatalf("server ReadTSDU = %v, want ErrDisconnected", err)
				}
			})
		})
	}
}

// The rule is for writes only. A read whose context ends before any octet
// arrived leaves a connection over TLS open, as over TCP: crypto/tls resumes
// a read after a deadline. Both directions carry TSDUs afterwards.
func TestTSDU_IdleReadTimeoutOverTLSKeepsOpen(t *testing.T) {
	cert, roots := testCertificate(t)
	synctest.Test(t, func(t *testing.T) {
		cli, srv := tlsPair(t, cert, roots)
		defer func() { _ = cli.Close(); _ = srv.Close() }()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := cli.ReadTSDU(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrClosed) {
			t.Fatalf("ReadTSDU = %v, want the bare DeadlineExceeded", err)
		}
		if cli.terminalKind() != terminalNone {
			t.Fatal("an idle read timeout over TLS must not end the connection")
		}

		for _, dir := range []struct {
			name     string
			from, to *Conn
		}{{"server to client", srv, cli}, {"client to server", cli, srv}} {
			sent := make(chan error, 1)
			go func() { sent <- dir.from.WriteTSDU(context.Background(), []byte("after the timeout")) }()
			got, err := dir.to.ReadTSDU(context.Background())
			if err != nil || !bytes.Equal(got, []byte("after the timeout")) {
				t.Fatalf("%s: ReadTSDU = %q, %v", dir.name, got, err)
			}
			if err := <-sent; err != nil {
				t.Fatalf("%s: WriteTSDU = %v", dir.name, err)
			}
		}
	})
}
