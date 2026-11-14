// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// connectionTimedOut is what a TCP read or write returns when the kernel
// gives up on the connection (keep-alive or retransmission without an
// answer): ETIMEDOUT inside a *net.OpError. Its Timeout method answers true,
// like a deadline expiry, but no deadline was involved.
func connectionTimedOut(op string) error {
	return &net.OpError{Op: op, Net: "tcp", Err: os.NewSyscallError(op, syscall.ETIMEDOUT)}
}

// timeoutContexts are the contexts a caller may hold when the stream times
// out underneath it: none of them has ended, or the one that has is not the
// reason the stream failed.
func timeoutContexts(t *testing.T) map[string]context.Context {
	t.Helper()
	far, cancelFar := context.WithTimeout(context.Background(), time.Hour)
	t.Cleanup(cancelFar)
	cancellable, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return map[string]context.Context{
		"no deadline":         context.Background(),
		"deadline in an hour": far,
		"cancellable":         cancellable,
	}
}

// assertDisconnect checks that err reports the stream going away with the
// kernel's error as its cause, and not a context that ended.
func assertDisconnect(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrDisconnected) {
		t.Fatalf("%s = %v, want ErrDisconnected", what, err)
	}
	var de *DisconnectError
	if !errors.As(err, &de) || !errors.Is(de.Cause, syscall.ETIMEDOUT) {
		t.Fatalf("%s = %v, want a *DisconnectError with cause ETIMEDOUT", what, err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("%s = %v, must not report a context that ended", what, err)
	}
	if errors.Is(err, ErrClosed) {
		t.Fatalf("%s = %v, must not report a local close", what, err)
	}
}

// A connection timeout from the kernel is a disconnect in the open state,
// whatever context the caller holds (ERRORS.md: ErrClosed joined with a
// context error is reserved for a context that ended).
func TestTSDU_ConnectionTimeoutIsDisconnect(t *testing.T) {
	nonFinal := mustEncodeTPKT(t, mustMarshal(t, &DT{EOT: false, UserData: []byte{1}}))

	for name, ctx := range timeoutContexts(t) {
		t.Run("read at a TSDU boundary/"+name, func(t *testing.T) {
			sc := newScriptConn(bytes.NewReader(nil))
			sc.readErr = connectionTimedOut("read")
			conn, refs := openScriptConn(t, sc, 1024, 0)

			_, err := conn.ReadTSDU(ctx)
			assertDisconnect(t, "ReadTSDU", err)
			if errors.Is(err, ErrIncompleteTSDU) {
				t.Fatalf("ReadTSDU = %v, no TSDU was in progress", err)
			}
			if conn.terminalKind() != terminalAborted || refs.Len() != 0 {
				t.Fatalf("terminal kind %v, %d references held; want aborted and released", conn.terminalKind(), refs.Len())
			}
			// The first cause stays: later calls report the disconnect too.
			assertDisconnect(t, "Close after the disconnect", conn.Close())
			assertDisconnect(t, "WriteTSDU after the disconnect", conn.WriteTSDU(ctx, []byte{1}))
		})

		t.Run("read inside a TSDU/"+name, func(t *testing.T) {
			sc := newScriptConn(bytes.NewReader(nonFinal))
			sc.readErr = connectionTimedOut("read")
			conn, _ := openScriptConn(t, sc, 1024, 0)

			_, err := conn.ReadTSDU(ctx)
			assertDisconnect(t, "ReadTSDU", err)
			if !errors.Is(err, ErrIncompleteTSDU) {
				t.Fatalf("ReadTSDU = %v, want ErrIncompleteTSDU joined", err)
			}
		})

		t.Run("write/"+name, func(t *testing.T) {
			sc := newScriptConn(bytes.NewReader(nil))
			sc.writeErr = connectionTimedOut("write")
			conn, refs := openScriptConn(t, sc, 1024, 0)

			err := conn.WriteTSDU(ctx, []byte("request"))
			assertDisconnect(t, "WriteTSDU", err)
			if conn.terminalKind() != terminalAborted || refs.Len() != 0 {
				t.Fatalf("terminal kind %v, %d references held; want aborted and released", conn.terminalKind(), refs.Len())
			}
		})
	}
}

// The same during the handshake: Connect and Accept report the disconnect,
// close the stream and hold no reference.
func TestHandshake_ConnectionTimeoutIsDisconnect(t *testing.T) {
	cr := mustEncodeTPKT(t, mustMarshal(t, &CR{SourceRef: 7, TPDUSize: new(uint8(0x0A))}))

	for name, ctx := range timeoutContexts(t) {
		t.Run("Connect awaiting the CC/"+name, func(t *testing.T) {
			held := defaultRefs.Len()
			sc := newScriptConn(bytes.NewReader(nil))
			sc.readErr = connectionTimedOut("read")

			conn, err := Connect(ctx, sc, ClientConfig{MaxTPDULength: 1024})
			assertDisconnect(t, "Connect", err)
			assertHandshakeReleased(t, conn, sc, held)
		})

		t.Run("Connect writing the CR/"+name, func(t *testing.T) {
			held := defaultRefs.Len()
			sc := newScriptConn(bytes.NewReader(nil))
			sc.writeErr = connectionTimedOut("write")

			conn, err := Connect(ctx, sc, ClientConfig{MaxTPDULength: 1024})
			assertDisconnect(t, "Connect", err)
			assertHandshakeReleased(t, conn, sc, held)
		})

		t.Run("Accept awaiting the CR/"+name, func(t *testing.T) {
			held := defaultRefs.Len()
			sc := newScriptConn(bytes.NewReader(nil))
			sc.readErr = connectionTimedOut("read")

			conn, err := Accept(ctx, sc, ServerConfig{MaxTPDULength: 1024})
			assertDisconnect(t, "Accept", err)
			assertHandshakeReleased(t, conn, sc, held)
		})

		t.Run("Accept writing the CC/"+name, func(t *testing.T) {
			held := defaultRefs.Len()
			sc := newScriptConn(bytes.NewReader(cr))
			sc.writeErr = connectionTimedOut("write")

			conn, err := Accept(ctx, sc, ServerConfig{MaxTPDULength: 1024})
			assertDisconnect(t, "Accept", err)
			assertHandshakeReleased(t, conn, sc, held)
		})
	}
}

// assertHandshakeReleased checks what a failed Connect or Accept leaves
// behind: no Conn, a closed stream, and the reference count it started with.
func assertHandshakeReleased(t *testing.T, conn *Conn, sc *scriptConn, held int) {
	t.Helper()
	if conn != nil {
		t.Fatal("a failed handshake returned a Conn")
	}
	if n := sc.closes.Load(); n == 0 {
		t.Fatal("a failed handshake left the stream open")
	}
	if got := defaultRefs.Len(); got != held {
		t.Fatalf("%d references held after the failed handshake, %d before", got, held)
	}
}

// A context that has ended does not turn the kernel's connection timeout
// into a context error, and a deadline expiry stays one.
func TestClassify_ConnectionTimeoutAgainstContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

	for name, ctx := range map[string]context.Context{"cancelled": cancelled, "deadline passed": expired} {
		t.Run(name, func(t *testing.T) {
			conn, _ := openScriptConn(t, newScriptConn(bytes.NewReader(nil)), 1024, 0)
			assertDisconnect(t, "classifyIOPhase", conn.classifyIOPhase(ctx, connectionTimedOut("read"), false))
			assertDisconnect(t, "connectIOError", connectIOError(ctx, connectionTimedOut("read")))

			// The stream deadline armed for ctx is still the context ending.
			conn, _ = openScriptConn(t, newScriptConn(bytes.NewReader(nil)), 1024, 0)
			if err := conn.classifyIOPhase(ctx, os.ErrDeadlineExceeded, false); !errors.Is(err, ErrClosed) || !errors.Is(err, ctx.Err()) {
				t.Fatalf("deadline expiry = %v, want ErrClosed joined with %v", err, ctx.Err())
			}
			if err := connectIOError(ctx, os.ErrDeadlineExceeded); !errors.Is(err, ErrClosed) || !errors.Is(err, ctx.Err()) {
				t.Fatalf("handshake deadline expiry = %v, want ErrClosed joined with %v", err, ctx.Err())
			}
		})
	}

	if isTimeout(connectionTimedOut("read")) {
		t.Fatal("isTimeout must not take the kernel's connection timeout for a deadline expiry")
	}
	if !isTimeout(os.ErrDeadlineExceeded) {
		t.Fatal("isTimeout must recognise a deadline expiry")
	}
	if idle := (&Conn{}).idleTimeout(expired, connectionTimedOut("read")); idle != nil {
		t.Fatalf("idleTimeout = %v: a connection timeout must not leave the connection open with a context error", idle)
	}
}

// The zero Conn is not a connection: its operations return ErrClosed at
// once instead of waiting for a stream that does not exist.
func TestConn_ZeroValueReturnsErrClosed(t *testing.T) {
	type result struct {
		op  string
		err error
	}
	results := make(chan result, 2)
	go func() {
		var c Conn
		_, err := c.ReadTSDU(context.Background())
		results <- result{"ReadTSDU", err}
	}()
	go func() {
		c := new(Conn)
		results <- result{"WriteTSDU", c.WriteTSDU(context.Background(), []byte{1})}
	}()
	for range 2 {
		select {
		case r := <-results:
			if !errors.Is(r.err, ErrClosed) {
				t.Errorf("%s on a zero Conn = %v, want ErrClosed", r.op, r.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ReadTSDU or WriteTSDU on a zero Conn did not return")
		}
	}

	var c Conn
	if err := c.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close on a zero Conn = %v, want ErrClosed", err)
	}
	if _, err := c.ReadTSDU(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReadTSDU after Close on a zero Conn = %v, want ErrClosed", err)
	}
	if err := c.WriteTSDU(context.Background(), []byte{1}); !errors.Is(err, ErrClosed) {
		t.Fatalf("WriteTSDU after Close on a zero Conn = %v, want ErrClosed", err)
	}
}
