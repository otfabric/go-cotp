// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// Contract tests of the lifecycle matrix (otfabric/engineering
// standards/lifecycle.md, rows L1 to L16) for *Conn, the one long-lived type
// of this package. TESTING.md lists every row with its tests and the reason
// for each row that does not apply.
//
// The tests decide the interleaving themselves: net.Pipe inside a
// testing/synctest bubble, where synctest.Wait returns once every goroutine
// is blocked, or a scriptConn that reports when its reader waits for more.

// Contract matrix L2: several goroutines call Close while a read is blocked.
// Every call returns ErrClosed, the stream is closed once, the reference is
// released once, and the blocked read returns ErrClosed.
func TestLifecycle_ConcurrentClose(t *testing.T) {
	sc := newScriptConn(bytes.NewReader(nil))
	conn, refs := openScriptConn(t, sc, 1024, 0)
	ref := conn.localRef
	if !refs.Active(ref) {
		t.Fatal("the reference of an open connection must be held")
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := conn.ReadTSDU(context.Background())
		readErr <- err
	}()
	sc.awaitIdle(t) // ReadTSDU waits for its first octet

	const closers = 16
	start := make(chan struct{})
	errs := make([]error, closers)
	var wg sync.WaitGroup
	for i := range closers {
		wg.Go(func() {
			<-start
			errs[i] = conn.Close()
		})
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Close %d = %v, want ErrClosed", i, err)
		}
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("blocked ReadTSDU = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked ReadTSDU did not return after Close")
	}
	if n := sc.closes.Load(); n != 1 {
		t.Fatalf("the stream was closed %d times, want once", n)
	}
	if refs.Len() != 0 || conn.terminalKind() != terminalClosed {
		t.Fatalf("%d references held, terminal kind %v; want none and closed", refs.Len(), conn.terminalKind())
	}

	// The reference value is free for another connection now. A later Close
	// of this one must not release it a second time.
	refs.mu.Lock()
	refs.active[ref] = struct{}{}
	refs.mu.Unlock()
	if err := conn.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close after Close = %v, want ErrClosed", err)
	}
	if !refs.Active(ref) {
		t.Fatal("a repeated Close released the reference again")
	}
	if n := sc.closes.Load(); n != 1 {
		t.Fatalf("the stream was closed %d times after a repeated Close, want once", n)
	}
}

// Contract matrix L4: Close while a write has put part of a segment on the
// stream. The write returns ErrClosed, and the stream ends where the write
// stopped: nothing follows the interrupted segment.
func TestLifecycle_CloseDuringWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const maxTPDU = 128
		cli, srv := openPipePair(t, maxTPDU, DefaultMaxTSDULength)
		peer := srv.raw // the peer reads the stream below the service

		writeErr := make(chan error, 1)
		go func() {
			// Eight segments at this TPDU size.
			writeErr <- cli.WriteTSDU(context.Background(), bytes.Repeat([]byte{0x5A}, 1000))
		}()

		// The peer takes the first segment and half of the second, then
		// stops reading.
		const packet = 4 + maxTPDU // TPKT header and a full DT
		taken := make([]byte, packet+packet/2)
		if _, err := io.ReadFull(peer, taken); err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // WriteTSDU is blocked inside its second segment
		select {
		case err := <-writeErr:
			t.Fatalf("WriteTSDU returned %v with the peer not reading", err)
		default:
		}

		if err := cli.Close(); !errors.Is(err, ErrClosed) {
			t.Fatalf("Close = %v, want ErrClosed", err)
		}
		select {
		case err := <-writeErr:
			if !errors.Is(err, ErrClosed) || errors.Is(err, ErrDisconnected) {
				t.Fatalf("interrupted WriteTSDU = %v, want ErrClosed and not a disconnect", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("WriteTSDU not unblocked by Close")
		}
		if err := cli.WriteTSDU(context.Background(), []byte{1}); !errors.Is(err, ErrClosed) {
			t.Fatalf("WriteTSDU after Close = %v, want ErrClosed", err)
		}

		// What the peer received: one whole segment, then the stream ends.
		first, err := Decode(taken[4:packet])
		if err != nil || first.Type != TypeDT || first.DT.EOT || len(first.DT.UserData) != maxTPDU-3 {
			t.Fatalf("first segment: %v, %v", first.DT, err)
		}
		rest, err := io.ReadAll(peer)
		if err != nil || len(rest) != 0 {
			t.Fatalf("%d octets followed the interrupted segment (%v), want the end of the stream", len(rest), err)
		}
	})
}

type handshakeResult struct {
	conn *Conn
	err  error
}

// assertHandshakeEnded checks what a handshake that did not complete leaves
// behind: an error matching every sentinel of want, no Conn, the reference
// count it started with, and a closed stream (the peer reads its end).
func assertHandshakeEnded(t *testing.T, what string, res handshakeResult, held int, peer net.Conn, want ...error) {
	t.Helper()
	for _, w := range want {
		if !errors.Is(res.err, w) {
			t.Fatalf("%s = %v, want %v", what, res.err, w)
		}
	}
	if res.conn != nil {
		t.Fatalf("%s returned a Conn beside its error", what)
	}
	if got := defaultRefs.Len(); got != held {
		t.Fatalf("%s: %d references held afterwards, %d before", what, got, held)
	}
	if peer != nil {
		if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("%s left its stream open: the peer read %d octets, %v", what, n, err)
		}
	}
}

// Contract matrix L5: no Conn exists during the handshake, so the row is the
// context of Connect or Accept ending while the handshake waits on the
// stream. The call fails with ErrClosed and the context's error, releases its
// reference and closes the stream.
func TestLifecycle_HandshakeContextEnds(t *testing.T) {
	const deadline = 5 * time.Second

	// Each entry returns a context, the function that ends it and the error
	// it ends with: by cancelling, or by doing nothing and letting the
	// deadline pass on the bubble's clock.
	contexts := map[string]func(t *testing.T) (ctx context.Context, end func(), want error){
		"cancelled": func(t *testing.T) (context.Context, func(), error) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			return ctx, cancel, context.Canceled
		},
		"deadline": func(t *testing.T) (context.Context, func(), error) {
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			t.Cleanup(cancel)
			return ctx, func() {}, context.DeadlineExceeded
		},
	}

	for name, newContext := range contexts {
		t.Run("Accept waiting for the CR/"+name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				held := defaultRefs.Len()
				peer, stream := net.Pipe()
				defer func() { _ = peer.Close() }()
				ctx, end, want := newContext(t)
				started := time.Now()

				resCh := make(chan handshakeResult, 1)
				go func() {
					conn, err := Accept(ctx, stream, ServerConfig{MaxTPDULength: 1024})
					resCh <- handshakeResult{conn, err}
				}()
				synctest.Wait() // Accept is blocked reading the CR
				end()

				assertHandshakeEnded(t, "Accept", <-resCh, held, peer, ErrClosed, want)
				if want == context.DeadlineExceeded && time.Since(started) != deadline {
					t.Fatalf("Accept returned after %v, want the context's %v", time.Since(started), deadline)
				}
			})
		})

		t.Run("Accept writing the CC/"+name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				held := defaultRefs.Len()
				peer, stream := net.Pipe()
				defer func() { _ = peer.Close() }()
				ctx, end, want := newContext(t)

				resCh := make(chan handshakeResult, 1)
				go func() {
					conn, err := Accept(ctx, stream, ServerConfig{MaxTPDULength: 1024})
					resCh <- handshakeResult{conn, err}
				}()
				// The peer sends its CR and does not read the answer.
				writePeerCR(t, peer, &CR{SourceRef: 7, TPDUSize: new(uint8(0x0A))})
				synctest.Wait() // Accept is blocked writing the CC
				if got := defaultRefs.Len(); got != held+1 {
					t.Fatalf("%d references held while the CC is written, want %d", got, held+1)
				}
				end()

				// The stream is closed with the CC unread: the peer's read ends.
				assertHandshakeEnded(t, "Accept", <-resCh, held, peer, ErrClosed, want)
			})
		})

		t.Run("Connect waiting for the CC/"+name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				held := defaultRefs.Len()
				stream, peer := net.Pipe()
				defer func() { _ = peer.Close() }()
				ctx, end, want := newContext(t)
				started := time.Now()

				resCh := make(chan handshakeResult, 1)
				go func() {
					conn, err := Connect(ctx, stream, ClientConfig{MaxTPDULength: 1024})
					resCh <- handshakeResult{conn, err}
				}()
				_ = readPeerCR(t, peer) // the peer takes the CR and does not answer
				synctest.Wait()         // Connect is blocked reading the CC
				if got := defaultRefs.Len(); got != held+1 {
					t.Fatalf("%d references held while the CC is awaited, want %d", got, held+1)
				}
				end()

				assertHandshakeEnded(t, "Connect", <-resCh, held, peer, ErrClosed, want)
				if want == context.DeadlineExceeded && time.Since(started) != deadline {
					t.Fatalf("Connect returned after %v, want the context's %v", time.Since(started), deadline)
				}
			})
		})
	}
}

// Without a deadline on its context a handshake waits for as long as the
// peer stays silent (SECURITY.md "Resource limits"): the caller sets the bound.
func TestLifecycle_HandshakeWithoutDeadlineWaits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		peer, stream := net.Pipe()
		resCh := make(chan handshakeResult, 1)
		go func() {
			conn, err := Accept(context.Background(), stream, ServerConfig{MaxTPDULength: 1024})
			resCh <- handshakeResult{conn, err}
		}()

		<-time.After(24 * time.Hour) // on the bubble's clock: the peer stays silent for a day
		synctest.Wait()
		select {
		case res := <-resCh:
			t.Fatalf("Accept without a deadline returned on its own: %v, %v", res.conn, res.err)
		default:
		}

		_ = peer.Close()
		res := <-resCh
		if !errors.Is(res.err, ErrDisconnected) || res.conn != nil {
			t.Fatalf("Accept after the peer closed = %v, %v; want ErrDisconnected", res.conn, res.err)
		}
	})
}

// Contract matrix L11: an OnConnect callback that takes its time holds up its
// own handshake and nothing else. While it runs, another connection is
// established and carries data; when it returns, its handshake completes.
// The two connections share nothing but the reference allocator (L13).
func TestLifecycle_SlowOnConnectStallsOnlyItsHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		slowClientEnd, slowServerEnd := net.Pipe()
		entered := make(chan struct{})
		release := make(chan struct{})

		serverCh := make(chan handshakeResult, 1)
		go func() {
			conn, err := Accept(context.Background(), slowServerEnd, ServerConfig{
				MaxTPDULength: 1024,
				OnConnect: func(context.Context, ConnectIndication) (AcceptDecision, error) {
					close(entered)
					<-release
					return AcceptDecision{Action: ConnectAccept}, nil
				},
			})
			serverCh <- handshakeResult{conn, err}
		}()
		clientCh := make(chan handshakeResult, 1)
		go func() {
			conn, err := Connect(context.Background(), slowClientEnd, ClientConfig{MaxTPDULength: 1024})
			clientCh <- handshakeResult{conn, err}
		}()
		<-entered
		synctest.Wait() // the callback is running; both ends of its handshake wait

		// Another connection is established and used meanwhile.
		cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
		exchange(t, cli, srv, []byte("request on the other connection"))
		exchange(t, srv, cli, []byte("response on the other connection"))

		synctest.Wait()
		select {
		case res := <-serverCh:
			t.Fatalf("Accept returned (%v, %v) while its OnConnect was running", res.conn, res.err)
		case res := <-clientCh:
			t.Fatalf("Connect returned (%v, %v) while the peer's OnConnect was running", res.conn, res.err)
		default:
		}

		close(release)
		slowSrv, slowCli := <-serverCh, <-clientCh
		if slowSrv.err != nil || slowCli.err != nil {
			t.Fatalf("handshake after the callback returned: Accept %v, Connect %v", slowSrv.err, slowCli.err)
		}
		defer func() {
			_ = slowCli.conn.Close()
			_ = slowSrv.conn.Close()
		}()

		// Four connections, four references; data stays on its connection.
		refs := map[uint16]bool{}
		for _, c := range []*Conn{cli, srv, slowCli.conn, slowSrv.conn} {
			refs[c.Negotiated().LocalRef] = true
		}
		if len(refs) != 4 {
			t.Fatalf("local references of four connections: %v, want four distinct values", refs)
		}
		exchange(t, slowCli.conn, slowSrv.conn, []byte("request on the slow connection"))
		exchange(t, cli, srv, []byte("second request on the other connection"))
	})
}

// exchange sends tsdu from one end of a connection and expects exactly it at
// the other end.
func exchange(t *testing.T, from, to *Conn, tsdu []byte) {
	t.Helper()
	writeErr := make(chan error, 1)
	go func() { writeErr <- from.WriteTSDU(context.Background(), tsdu) }()
	got, err := to.ReadTSDU(context.Background())
	if err != nil || !bytes.Equal(got, tsdu) {
		t.Fatalf("ReadTSDU = %q, %v; want %q", got, err, tsdu)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("WriteTSDU: %v", err)
	}
}

// Contract matrix L14: a Connect that fails returns no Conn, releases its
// reference and closes the stream, whatever made it fail.
func TestLifecycle_FailedConnectReleasesEverything(t *testing.T) {
	answer := func(build func(cr *CR) []byte) func(net.Conn) error {
		return func(peer net.Conn) error {
			cr, err := peerReadCR(peer)
			if err != nil {
				return err
			}
			return peerWriteTPDU(peer, build(cr))
		}
	}
	marshal := func(v interface{ MarshalBinary() ([]byte, error) }) []byte { return mustMarshal(t, v) }

	cases := []struct {
		name string
		cfg  ClientConfig
		peer func(net.Conn) error // nil: the peer never sees a CR
		// peerCloses: the peer ends the stream itself after peer returns.
		peerCloses bool
		want       error
	}{
		{name: "invalid configuration", cfg: ClientConfig{MaxTPDULength: 50}, want: ErrInvalidConfig},
		{name: "connect data too long", cfg: ClientConfig{ConnectData: make([]byte, MaxConnectDataLength+1)}, want: ErrInvalidConfig},
		{name: "refused with a DR", want: ErrConnectionRefused, peer: answer(func(cr *CR) []byte {
			return marshal(&DR{DestinationRef: cr.SourceRef, Reason: uint8(ReasonCongestionAtTSAP)})
		})},
		{name: "answered with an ER", want: ErrHandshake, peer: answer(func(cr *CR) []byte {
			return marshal(&ER{DestinationRef: cr.SourceRef, RejectCause: 3})
		})},
		{name: "answered with a DT", want: ErrUnexpectedTPDU, peer: answer(func(*CR) []byte {
			return marshal(&DT{EOT: true, UserData: []byte{1}})
		})},
		{name: "answered with a malformed TPDU", want: ErrHandshake, peer: answer(func(*CR) []byte {
			return []byte{0x06, 0xD0, 0x00}
		})},
		{name: "CC for another reference", want: ErrHandshake, peer: answer(func(cr *CR) []byte {
			return marshal(&CC{DestinationRef: cr.SourceRef + 1, SourceRef: 9, TPDUSize: new(uint8(0x0A))})
		})},
		{name: "CC with source reference zero", want: ErrHandshake, peer: answer(func(cr *CR) []byte {
			return marshal(&CC{DestinationRef: cr.SourceRef, SourceRef: 0, TPDUSize: new(uint8(0x0A))})
		})},
		{name: "CC with a credit", want: ErrHandshake, peer: answer(func(cr *CR) []byte {
			return marshal(&CC{CDT: 1, DestinationRef: cr.SourceRef, SourceRef: 9, TPDUSize: new(uint8(0x0A))})
		})},
		{name: "CC selecting more than was offered", want: ErrHandshake, peer: answer(func(cr *CR) []byte {
			return marshal(&CC{DestinationRef: cr.SourceRef, SourceRef: 9, TPDUSize: new(uint8(0x0B))})
		})},
		{name: "CC with too much connect data", want: ErrHandshake, peer: answer(func(cr *CR) []byte {
			return marshal(&CC{DestinationRef: cr.SourceRef, SourceRef: 9, TPDUSize: new(uint8(0x0A)), UserData: make([]byte, MaxConnectDataLength+1)})
		})},
		{name: "TPKT version violated", want: ErrHandshake, peer: func(peer net.Conn) error {
			if _, err := peerReadCR(peer); err != nil {
				return err
			}
			// The client stops reading at the version octet, so this write
			// ends when the client closes the stream.
			_, _ = peer.Write([]byte{0x04, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80})
			return nil
		}},
		{name: "peer closes after the CR", want: ErrDisconnected, peerCloses: true, peer: func(peer net.Conn) error {
			_, err := peerReadCR(peer)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			held := defaultRefs.Len()
			stream, peer := net.Pipe()
			peerDone := make(chan error, 1)
			go func() {
				defer func() { _ = peer.Close() }()
				if tc.peer != nil {
					if err := tc.peer(peer); err != nil {
						peerDone <- err
						return
					}
				}
				if tc.peerCloses {
					peerDone <- nil
					return
				}
				// Whatever was answered, the client must close the stream.
				if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
					peerDone <- errors.New("the client left its stream open")
					return
				}
				peerDone <- nil
			}()

			cfg := tc.cfg
			if cfg.MaxTPDULength == 0 {
				cfg.MaxTPDULength = 1024
			}
			conn, err := Connect(context.Background(), stream, cfg)
			assertHandshakeEnded(t, "Connect", handshakeResult{conn, err}, held, nil, tc.want)
			select {
			case err := <-peerDone:
				if err != nil {
					t.Fatalf("peer: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the peer did not see the stream close")
			}
		})
	}
}
