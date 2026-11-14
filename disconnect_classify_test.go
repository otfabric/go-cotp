// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/otfabric/go-tpkt"
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

// A failure inside a TPKT packet ends the connection, and the call after it
// returns the same terminal error. go-tpkt (v1.2.0 and later) keeps a Reader
// or Writer that failed inside a packet in a failed state, and every later
// call on it returns tpkt.ErrStreamMisaligned; go-cotp has ended the
// connection at the first failure, so that error does not reach the caller.
func TestTSDU_MidPacketFailureThenNextCall(t *testing.T) {
	packet := func(t *testing.T) []byte {
		return mustEncodeTPKT(t, mustMarshal(t, &DT{EOT: true, UserData: []byte{1, 2, 3}}))
	}
	cases := []struct {
		name string
		// fail makes one call fail inside a packet; next is the call after it.
		fail func(t *testing.T, cli, srv *Conn) error
		next func(srv *Conn) error
		want []error
	}{
		{
			name: "read, deadline inside a packet",
			fail: func(t *testing.T, cli, srv *Conn) error {
				go func() { _, _ = cli.raw.Write(packet(t)[:5]) }() // the header and one octet
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_, err := srv.ReadTSDU(ctx)
				return err
			},
			next: func(srv *Conn) error { _, err := srv.ReadTSDU(context.Background()); return err },
			want: []error{ErrClosed, context.DeadlineExceeded},
		},
		{
			name: "read, end of the stream inside a packet",
			fail: func(t *testing.T, cli, srv *Conn) error {
				go func() {
					_, _ = cli.raw.Write(packet(t)[:5])
					_ = cli.raw.Close()
				}()
				_, err := srv.ReadTSDU(context.Background())
				return err
			},
			next: func(srv *Conn) error { _, err := srv.ReadTSDU(context.Background()); return err },
			want: []error{ErrDisconnected, ErrIncompleteTSDU},
		},
		{
			name: "write, deadline inside a packet",
			fail: func(t *testing.T, cli, srv *Conn) error {
				go func() { _, _ = io.ReadFull(cli.raw, make([]byte, 2)) }() // two octets of the header
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				return srv.WriteTSDU(ctx, []byte{1, 2, 3})
			},
			next: func(srv *Conn) error { return srv.WriteTSDU(context.Background(), []byte{4}) },
			want: []error{ErrClosed, context.DeadlineExceeded},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
				check := func(what string, err error) {
					t.Helper()
					for _, w := range tc.want {
						if !errors.Is(err, w) {
							t.Fatalf("%s = %v, want %v", what, err, tc.want)
						}
					}
					if errors.Is(err, tpkt.ErrStreamMisaligned) {
						t.Fatalf("%s = %v: the TPKT state must not reach the caller", what, err)
					}
				}
				check("the failing call", tc.fail(t, cli, srv))
				if srv.terminalKind() != terminalAborted {
					t.Fatalf("terminal kind %v after a failure inside a packet, want aborted", srv.terminalKind())
				}
				check("the next call", tc.next(srv))
				check("Close", srv.Close())
			})
		})
	}
}

// shortWriteConn is a scriptConn whose stream accepts the first n octets
// written to it and fails every write after them with err.
type shortWriteConn struct {
	*scriptConn
	n   int
	err error
}

func (s *shortWriteConn) Write(p []byte) (int, error) {
	k := min(len(p), s.n)
	s.n -= k
	if k < len(p) {
		return k, s.err
	}
	return k, nil
}

// Should the TPKT reader or writer of an open connection be in go-tpkt's
// failed state, the call ends the connection with ErrClosed whatever the
// earlier failure was: the stream is not on a packet boundary. A deadline
// that the error wraps is not taken for the end of this call's context, and
// the connection is not left open as after an idle timeout.
func TestClassify_MisalignedStreamEndsConnection(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	assertEnded := func(t *testing.T, what string, conn *Conn, refs *referenceAllocator, err error) {
		t.Helper()
		if !errors.Is(err, ErrClosed) || !errors.Is(err, tpkt.ErrStreamMisaligned) {
			t.Fatalf("%s = %v, want ErrClosed joined with tpkt.ErrStreamMisaligned", what, err)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			t.Fatalf("%s = %v: the context of this call has not ended", what, err)
		}
		if conn.terminalKind() != terminalAborted || refs.Len() != 0 {
			t.Fatalf("terminal kind %v, %d references held; want aborted and released", conn.terminalKind(), refs.Len())
		}
	}
	for name, ctx := range timeoutContexts(t) {
		t.Run("read/"+name, func(t *testing.T) {
			// Two octets of a TPKT header, then the stream times out.
			sc := newScriptConn(bytes.NewReader([]byte{0x03, 0x00}))
			sc.readErr = timeout
			conn, refs := openScriptConn(t, sc, 1024, 0)
			if _, err := conn.reader.ReadPacket(); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("setup: ReadPacket = %v, want the timeout", err)
			}
			_, err := conn.ReadTSDU(ctx)
			assertEnded(t, "ReadTSDU", conn, refs, err)
			_, err = conn.ReadTSDU(ctx)
			assertEnded(t, "the next ReadTSDU", conn, refs, err)
		})
		t.Run("write/"+name, func(t *testing.T) {
			// Two octets of a TPKT packet leave, then the stream times out.
			sw := &shortWriteConn{scriptConn: newScriptConn(bytes.NewReader(nil)), n: 2, err: timeout}
			conn, refs := openScriptConn(t, sw, 1024, 0)
			if err := conn.writer.WritePacket([]byte{0x02, 0xF0, 0x80, 0x01}); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("setup: WritePacket = %v, want the timeout", err)
			}
			assertEnded(t, "WriteTSDU", conn, refs, conn.WriteTSDU(ctx, []byte{1}))
			assertEnded(t, "the next WriteTSDU", conn, refs, conn.WriteTSDU(ctx, []byte{1}))
		})
	}
}
