// SPDX-License-Identifier: MIT

package cotp_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/otfabric/go-cotp"
)

// The peer closes the stream while Connect is blocked on it: Connect returns
// the stream's error and no Conn.
func TestLeak_CloseUnblocksConnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer func() { _ = c2.Close() }()
		type result struct {
			conn *cotp.Conn
			err  error
		}
		resCh := make(chan result, 1)
		go func() {
			conn, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{MaxTPDULength: 1024})
			resCh <- result{conn, err}
		}()
		synctest.Wait() // Connect is blocked writing its CR: the peer does not read
		_ = c2.Close()
		select {
		case res := <-resCh:
			if !errors.Is(res.err, io.ErrClosedPipe) || res.conn != nil {
				t.Fatalf("Connect = %v, %v; want the closed-stream error and no Conn", res.conn, res.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Connect not unblocked")
		}
		// Connect closed its end of the stream.
		if _, err := c1.Write([]byte{0}); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("stream after the failed Connect: %v, want closed", err)
		}
	})
}

// The peer closes the stream while Accept waits for the CR: Accept reports
// the disconnect and returns no Conn.
func TestLeak_CloseUnblocksAccept(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer func() { _ = c1.Close() }()
		type result struct {
			conn *cotp.Conn
			err  error
		}
		resCh := make(chan result, 1)
		go func() {
			conn, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
			resCh <- result{conn, err}
		}()
		synctest.Wait() // Accept is blocked reading the CR
		_ = c1.Close()
		select {
		case res := <-resCh:
			if !errors.Is(res.err, cotp.ErrDisconnected) || !errors.Is(res.err, io.EOF) || res.conn != nil {
				t.Fatalf("Accept = %v, %v; want ErrDisconnected with EOF and no Conn", res.conn, res.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Accept not unblocked")
		}
		// Accept closed its end of the stream.
		if _, err := c2.Write([]byte{0}); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("stream after the failed Accept: %v, want closed", err)
		}
	})
}

// Contract matrix L3: Close during a blocked read.
func TestLeak_CloseUnblocksReadTSDU(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cli, srv := openTP0Pair(t,
			cotp.ClientConfig{MaxTPDULength: 1024},
			cotp.ServerConfig{MaxTPDULength: 1024},
		)
		errCh := make(chan error, 1)
		go func() {
			_, err := srv.ReadTSDU(context.Background())
			errCh <- err
		}()
		synctest.Wait() // ReadTSDU is blocked on the stream
		if err := srv.Close(); !errors.Is(err, cotp.ErrClosed) {
			t.Fatalf("Close: %v", err)
		}
		select {
		case err := <-errCh:
			if !errors.Is(err, cotp.ErrClosed) || errors.Is(err, cotp.ErrDisconnected) {
				t.Fatalf("ReadTSDU after Close = %v, want ErrClosed and not a disconnect", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ReadTSDU not unblocked")
		}
		// Operations started after Close fail at once with ErrClosed.
		if _, err := srv.ReadTSDU(context.Background()); !errors.Is(err, cotp.ErrClosed) {
			t.Fatalf("ReadTSDU after Close = %v, want ErrClosed", err)
		}
		_ = cli.Close()
	})
}

// Contract matrix L4: Close during a blocked write.
func TestLeak_CloseUnblocksWriteTSDU(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cli, srv := openTP0Pair(t,
			cotp.ClientConfig{MaxTPDULength: 128},
			cotp.ServerConfig{MaxTPDULength: 128},
		)
		// Do not read on the peer so the writer blocks on the pipe.
		errCh := make(chan error, 1)
		go func() {
			errCh <- cli.WriteTSDU(context.Background(), make([]byte, 64*1024))
		}()
		synctest.Wait() // WriteTSDU is blocked on the stream
		if err := cli.Close(); !errors.Is(err, cotp.ErrClosed) {
			t.Fatalf("Close: %v", err)
		}
		select {
		case err := <-errCh:
			if !errors.Is(err, cotp.ErrClosed) || errors.Is(err, cotp.ErrDisconnected) {
				t.Fatalf("WriteTSDU after Close = %v, want ErrClosed and not a disconnect", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("WriteTSDU not unblocked")
		}
		// Operations started after Close fail at once with ErrClosed, and
		// the peer sees the stream end: no segment follows the interrupted one.
		if err := cli.WriteTSDU(context.Background(), []byte{1}); !errors.Is(err, cotp.ErrClosed) {
			t.Fatalf("WriteTSDU after Close = %v, want ErrClosed", err)
		}
		if _, err := srv.ReadTSDU(context.Background()); !errors.Is(err, cotp.ErrDisconnected) {
			t.Fatalf("peer ReadTSDU = %v, want ErrDisconnected", err)
		}
		_ = srv.Close()
	})
}

func TestLeak_TimeoutGoroutineExits(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := srv.ReadTSDU(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadTSDU = %v, want context.DeadlineExceeded", err)
	}
	if errors.Is(err, cotp.ErrClosed) {
		t.Fatalf("idle timeout must not abort: %v", err)
	}
	// No octet was consumed, so the connection stays usable both ways.
	got := make(chan []byte, 1)
	go func() {
		b, _ := cli.ReadTSDU(context.Background())
		got <- b
	}()
	if err := srv.WriteTSDU(context.Background(), []byte{1}); err != nil {
		t.Fatalf("WriteTSDU after idle timeout: %v", err)
	}
	if b := <-got; len(b) != 1 || b[0] != 1 {
		t.Fatalf("peer got %v", b)
	}
	_ = cli.Close()
}

// Contract matrix L11: the peer goes away while OnConnect is still deciding.
// Accept runs the callback to its end, then fails on the CC it cannot write:
// it returns the stream's error and no Conn, and it has closed the stream.
func TestLeak_CallbackBlockedPeerCloses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer func() { _ = c1.Close() }()
		entered := make(chan struct{})
		release := make(chan struct{})
		type result struct {
			conn *cotp.Conn
			err  error
		}
		resCh := make(chan result, 1)
		go func() {
			conn, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{
				MaxTPDULength: 1024,
				OnConnect: func(context.Context, cotp.ConnectIndication) (cotp.AcceptDecision, error) {
					close(entered)
					<-release
					return cotp.AcceptDecision{Action: cotp.ConnectAccept}, nil
				},
			})
			resCh <- result{conn, err}
		}()

		// Valid CR so Accept enters OnConnect; peer closes while callback is blocked.
		writePeerTPDU(t, c1, mustMarshalTPDU(t, &cotp.CR{SourceRef: 9, TPDUSize: new(uint8(0x0A))}))
		<-entered
		_ = c1.Close()
		synctest.Wait()
		select {
		case res := <-resCh:
			t.Fatalf("Accept returned (%v, %v) while OnConnect was still running", res.conn, res.err)
		default:
		}
		close(release)

		select {
		case res := <-resCh:
			if !errors.Is(res.err, io.ErrClosedPipe) || res.conn != nil {
				t.Fatalf("Accept = %v, %v; want the closed-stream error of the CC write and no Conn", res.conn, res.err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Accept not unblocked after callback + peer close")
		}
		if _, err := c2.Write([]byte{0}); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("stream after the failed Accept: %v, want closed", err)
		}
	})
}

// A stream failure racing a local Close: whichever ends the connection
// first, the reader gets that cause, Close returns it, and it stays.
func TestLeak_ReadFailureRacesLocalClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cli, srv := openTP0Pair(t,
			cotp.ClientConfig{MaxTPDULength: 1024},
			cotp.ServerConfig{MaxTPDULength: 1024},
		)
		readErr := make(chan error, 1)
		go func() {
			_, err := srv.ReadTSDU(context.Background())
			readErr <- err
		}()
		synctest.Wait() // ReadTSDU is blocked on the stream

		start := make(chan struct{})
		closeErr := make(chan error, 1)
		var wg sync.WaitGroup
		wg.Go(func() {
			<-start
			closeErr <- srv.Close()
		})
		wg.Go(func() {
			<-start
			_ = cli.Close() // peer EOF racing local Close
		})
		close(start)
		wg.Wait()

		first := <-closeErr
		local := errors.Is(first, cotp.ErrClosed)
		remote := errors.Is(first, cotp.ErrDisconnected)
		if local == remote {
			t.Fatalf("Close = %v, want exactly one of ErrClosed and ErrDisconnected", first)
		}
		// The reader and every later call report the same first cause.
		for what, err := range map[string]error{
			"blocked ReadTSDU": <-readErr,
			"second Close":     srv.Close(),
			"later WriteTSDU":  srv.WriteTSDU(context.Background(), []byte{1}),
		} {
			if errors.Is(err, cotp.ErrClosed) != local || errors.Is(err, cotp.ErrDisconnected) != remote {
				t.Fatalf("%s = %v, the first cause was %v", what, err, first)
			}
		}
	})
}

func TestLeak_NoPipeGoroutineHangOnHandshakeFail(t *testing.T) {
	// Rapid failed handshakes should not leave blocked peer goroutines.
	for i := range 20 {
		c1, c2 := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { _ = c1.Close() }()
			writePeerTPDU(t, c1, []byte{0x02, 0x00, 0x00})
			buf := make([]byte, 1)
			_, _ = c1.Read(buf)
		}()
		_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
		if err == nil {
			t.Fatal("expected Accept failure")
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: peer goroutine leaked", i)
		}
	}
}
