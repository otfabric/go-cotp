// SPDX-License-Identifier: MIT

package cotp_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-cotp"
)

func openTCPPair(t *testing.T, clientCfg cotp.ClientConfig, serverCfg cotp.ServerConfig) (client, server *cotp.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	errCh := make(chan error, 1)
	var srv *cotp.Conn
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		srv, err = cotp.Accept(context.Background(), raw, serverCfg)
		errCh <- err
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli, err := cotp.Connect(context.Background(), raw, clientCfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
	})
	return cli, srv
}

func TestTCP_HandshakeAndRoundTrip(t *testing.T) {
	cli, srv := openTCPPair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	want := []byte("tcp-tp0")
	errCh := make(chan error, 1)
	var got []byte
	go func() {
		var err error
		got, err = srv.ReadTSDU(context.Background())
		errCh <- err
	}()
	if err := cli.WriteTSDU(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestTCP_SegmentedRequestResponse(t *testing.T) {
	cli, srv := openTCPPair(t,
		cotp.ClientConfig{MaxTPDULength: 128, MaxTSDULength: 10_000},
		cotp.ServerConfig{MaxTPDULength: 128, MaxTSDULength: 10_000},
	)
	req := bytes.Repeat([]byte{0x31}, 251)
	resp := bytes.Repeat([]byte{0x32}, 200)

	// Keep the client reader active before the server WriteTSDU reply so the
	// exchange does not depend on TCP buffering (same orchestration rule as
	// TestIntegration_SegmentedBothDirections on net.Pipe).
	type result struct {
		b   []byte
		err error
	}
	clientRead := make(chan result, 1)
	go func() {
		b, err := cli.ReadTSDU(context.Background())
		clientRead <- result{b, err}
	}()

	errCh := make(chan error, 1)
	go func() {
		got, err := srv.ReadTSDU(context.Background())
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(got, req) {
			errCh <- errors.New("server reassembly mismatch")
			return
		}
		errCh <- srv.WriteTSDU(context.Background(), resp)
	}()
	if err := cli.WriteTSDU(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	res := <-clientRead
	if res.err != nil {
		t.Fatal(res.err)
	}
	if !bytes.Equal(res.b, resp) {
		t.Fatalf("client got len=%d want=%d", len(res.b), len(resp))
	}
}

func TestTCP_FullDuplex(t *testing.T) {
	cli, srv := openTCPPair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	a := []byte("c2s-tcp")
	b := []byte("s2c-tcp")
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	wg.Add(4)
	go func() { defer wg.Done(); errs <- cli.WriteTSDU(context.Background(), a) }()
	go func() { defer wg.Done(); errs <- srv.WriteTSDU(context.Background(), b) }()
	go func() {
		defer wg.Done()
		got, err := srv.ReadTSDU(context.Background())
		if err != nil {
			errs <- err
			return
		}
		if !bytes.Equal(got, a) {
			errs <- errors.New("server got wrong payload")
			return
		}
		errs <- nil
	}()
	go func() {
		defer wg.Done()
		got, err := cli.ReadTSDU(context.Background())
		if err != nil {
			errs <- err
			return
		}
		if !bytes.Equal(got, b) {
			errs <- errors.New("client got wrong payload")
			return
		}
		errs <- nil
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestTCP_CloseEOF(t *testing.T) {
	cli, srv := openTCPPair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	errCh := make(chan error, 1)
	go func() {
		_, err := srv.ReadTSDU(context.Background())
		errCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := cli.Close(); !errors.Is(err, cotp.ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, cotp.ErrDisconnected) || !errors.Is(err, io.EOF) {
			t.Fatalf("server ReadTSDU after peer Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server not unblocked")
	}
}

func TestTCP_DeadlineCancelsRead(t *testing.T) {
	cli, srv := openTCPPair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	_ = cli // keep peer open so read blocks on empty stream
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := srv.ReadTSDU(ctx)
	if err == nil {
		t.Fatal("expected deadline/cancel error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, cotp.ErrClosed) {
		t.Fatalf("err = %v", err)
	}
	// Connection must be aborted after context-expired I/O.
	if err2 := srv.WriteTSDU(context.Background(), []byte{1}); err2 == nil {
		t.Fatal("write succeeded after deadline abort")
	}
}

func TestTCP_CancelUnblocksConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	// Accept TCP but never complete COTP handshake.
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		time.Sleep(2 * time.Second)
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_, err = cotp.Connect(ctx, raw, cotp.ClientConfig{MaxTPDULength: 1024})
	if err == nil {
		t.Fatal("expected connect timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, cotp.ErrClosed) {
		t.Fatalf("err = %v", err)
	}
}
