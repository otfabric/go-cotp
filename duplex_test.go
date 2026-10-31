// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Full-duplex regression tests: a context applied to one direction must
// never cut, extend, or clear the other direction's deadline.

func openTCPConnPair(t testing.TB, maxTPDU, maxTSDU int) (client, server *Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		server, err = Accept(context.Background(), raw, ServerConfig{MaxTPDULength: maxTPDU, MaxTSDULength: maxTSDU})
		errCh <- err
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err = Connect(context.Background(), raw, ClientConfig{MaxTPDULength: maxTPDU, MaxTSDULength: maxTSDU})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

type readResult struct {
	b   []byte
	err error
}

func goRead(c *Conn, ctx context.Context) <-chan readResult {
	ch := make(chan readResult, 1)
	go func() {
		b, err := c.ReadTSDU(ctx)
		ch <- readResult{b, err}
	}()
	return ch
}

func waitRead(t *testing.T, ch <-chan readResult, d time.Duration) readResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(d):
		t.Fatal("ReadTSDU did not return")
		return readResult{}
	}
}

// A reader blocked in ReadTSDU survives a concurrent WriteTSDU whose context
// expires while the write is stalled (nothing reached the stream).
func TestDuplex_ReadSurvivesWriteTimeout(t *testing.T) {
	t.Parallel()
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	reads := goRead(srv, context.Background())
	time.Sleep(10 * time.Millisecond) // let the reader block

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	// cli is not reading: on net.Pipe the write cannot move a single octet.
	err := srv.WriteTSDU(ctx, []byte("request"))
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrClosed) {
		t.Fatalf("WriteTSDU = %v, want bare DeadlineExceeded", err)
	}

	select {
	case r := <-reads:
		t.Fatalf("reader disturbed by write timeout: %v, %v", r.b, r.err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := cli.WriteTSDU(context.Background(), []byte("response")); err != nil {
		t.Fatal(err)
	}
	r := waitRead(t, reads, 2*time.Second)
	if r.err != nil || string(r.b) != "response" {
		t.Fatalf("ReadTSDU = %q, %v", r.b, r.err)
	}
}

// A reader blocked in ReadTSDU survives many concurrent WriteTSDU calls whose
// contexts are cancelled the moment they return (the cancellation callback
// must never fire into the read direction or into a later operation).
func TestDuplex_ReadSurvivesCancelledWrites(t *testing.T) {
	t.Parallel()
	cli, srv := openTCPConnPair(t, 1024, DefaultMaxTSDULength)
	reads := goRead(srv, context.Background())

	peerDone := make(chan error, 1)
	const n = 200
	go func() {
		for i := 0; i < n; i++ {
			if _, err := cli.ReadTSDU(context.Background()); err != nil {
				peerDone <- err
				return
			}
		}
		peerDone <- nil
	}()
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := srv.WriteTSDU(ctx, []byte{byte(i)})
		cancel()
		if err != nil {
			t.Fatalf("WriteTSDU %d: %v", i, err)
		}
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
	// Later writes are not poisoned by a stale cancellation deadline.
	if err := srv.WriteTSDU(context.Background(), []byte("tail")); err != nil {
		t.Fatalf("WriteTSDU after cancelled writes: %v", err)
	}
	if b, err := cli.ReadTSDU(context.Background()); err != nil || string(b) != "tail" {
		t.Fatalf("peer = %q, %v", b, err)
	}

	select {
	case r := <-reads:
		t.Fatalf("reader disturbed: %v, %v", r.b, r.err)
	default:
	}
	if err := cli.WriteTSDU(context.Background(), []byte("done")); err != nil {
		t.Fatal(err)
	}
	if r := waitRead(t, reads, 2*time.Second); r.err != nil || string(r.b) != "done" {
		t.Fatalf("ReadTSDU = %q, %v", r.b, r.err)
	}
}

// A completing write must not clear a concurrent reader's deadline.
func TestDuplex_WriteKeepsReadDeadline(t *testing.T) {
	t.Parallel()
	cli, srv := openTCPConnPair(t, 1024, DefaultMaxTSDULength)
	go func() {
		for {
			if _, err := cli.ReadTSDU(context.Background()); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	reads := goRead(srv, ctx)
	for time.Since(start) < 100*time.Millisecond {
		if err := srv.WriteTSDU(context.Background(), []byte("x")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	r := waitRead(t, reads, 2*time.Second)
	if !errors.Is(r.err, context.DeadlineExceeded) {
		t.Fatalf("ReadTSDU = %v, want DeadlineExceeded", r.err)
	}
	if srv.terminalKind() != terminalNone {
		t.Fatal("idle read timeout aborted the connection")
	}
}

// The reverse: a writer blocked in WriteTSDU survives a concurrent ReadTSDU
// whose context expires.
func TestDuplex_WriteSurvivesReadTimeout(t *testing.T) {
	t.Parallel()
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	writeErr := make(chan error, 1)
	go func() { writeErr <- srv.WriteTSDU(context.Background(), []byte("request")) }()
	time.Sleep(10 * time.Millisecond) // writer is stalled: cli is not reading

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := srv.ReadTSDU(ctx); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrClosed) {
		t.Fatalf("ReadTSDU = %v, want bare DeadlineExceeded", err)
	}
	select {
	case err := <-writeErr:
		t.Fatalf("writer disturbed by read timeout: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	b, err := cli.ReadTSDU(context.Background())
	if err != nil || string(b) != "request" {
		t.Fatalf("peer ReadTSDU = %q, %v", b, err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("WriteTSDU: %v", err)
	}
}

// A completing read must not clear a concurrent writer's deadline.
func TestDuplex_ReadKeepsWriteDeadline(t *testing.T) {
	t.Parallel()
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		for {
			if _, err := srv.ReadTSDU(context.Background()); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	writeErr := make(chan error, 1)
	// cli never reads, so srv's write stalls while srv's reads complete.
	go func() { writeErr <- srv.WriteTSDU(ctx, []byte("stalled")) }()
	deadline := time.After(2 * time.Second)
	for i := 0; ; i++ {
		if err := cli.WriteTSDU(context.Background(), []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-writeErr:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("WriteTSDU = %v, want DeadlineExceeded", err)
			}
			return
		case <-deadline:
			t.Fatal("write deadline lost: reads cleared it")
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A writer queued behind a stalled writer honours its own context and does
// not abort the connection.
func TestDuplex_QueuedWriterHonoursContext(t *testing.T) {
	t.Parallel()
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	first := make(chan error, 1)
	go func() { first <- srv.WriteTSDU(context.Background(), []byte("first")) }()
	time.Sleep(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := srv.WriteTSDU(ctx, []byte("second")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued WriteTSDU = %v, want DeadlineExceeded", err)
	}
	if b, err := cli.ReadTSDU(context.Background()); err != nil || string(b) != "first" {
		t.Fatalf("peer = %q, %v", b, err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}

	// Same for a queued reader.
	reads := goRead(cli, context.Background())
	time.Sleep(10 * time.Millisecond)
	rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer rcancel()
	if _, err := cli.ReadTSDU(rctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued ReadTSDU = %v, want DeadlineExceeded", err)
	}
	if err := srv.WriteTSDU(context.Background(), []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if r := waitRead(t, reads, 2*time.Second); r.err != nil || string(r.b) != "ok" {
		t.Fatalf("ReadTSDU = %q, %v", r.b, r.err)
	}
}

// A context cancelled (no deadline) while a write is stalled interrupts only
// that write.
func TestDuplex_CancelInterruptsOnlyItsDirection(t *testing.T) {
	t.Parallel()
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	reads := goRead(srv, context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	writeErr := make(chan error, 1)
	go func() { writeErr <- srv.WriteTSDU(ctx, []byte("x")) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-writeErr; !errors.Is(err, context.Canceled) || errors.Is(err, ErrClosed) {
		t.Fatalf("WriteTSDU = %v, want bare Canceled", err)
	}
	if err := cli.WriteTSDU(context.Background(), []byte("y")); err != nil {
		t.Fatal(err)
	}
	if r := waitRead(t, reads, 2*time.Second); r.err != nil || string(r.b) != "y" {
		t.Fatalf("ReadTSDU = %q, %v", r.b, r.err)
	}
}

// encodeTagged builds a self-checking TSDU: sender, seq, length, CRC, body.
func encodeTagged(sender, seq, n int) []byte {
	body := make([]byte, n)
	for i := range body {
		body[i] = byte(sender*31 + seq*7 + i)
	}
	out := make([]byte, 16+n)
	binary.BigEndian.PutUint32(out[0:], uint32(sender))
	binary.BigEndian.PutUint32(out[4:], uint32(seq))
	binary.BigEndian.PutUint32(out[8:], uint32(n))
	binary.BigEndian.PutUint32(out[12:], crc32.ChecksumIEEE(body))
	copy(out[16:], body)
	return out
}

func checkTagged(b []byte) (sender, seq int, err error) {
	if len(b) < 16 {
		return 0, 0, fmt.Errorf("short TSDU %d", len(b))
	}
	n := int(binary.BigEndian.Uint32(b[8:]))
	if len(b) != 16+n {
		return 0, 0, fmt.Errorf("length %d, header says %d", len(b), 16+n)
	}
	if crc32.ChecksumIEEE(b[16:]) != binary.BigEndian.Uint32(b[12:]) {
		return 0, 0, errors.New("CRC mismatch: segments interleaved")
	}
	return int(binary.BigEndian.Uint32(b[0:])), int(binary.BigEndian.Uint32(b[4:])), nil
}

// Many parallel senders alongside one reader per side: every TSDU arrives
// whole (segments of different TSDUs never interleave), per-sender order is
// kept, and the opposite direction keeps flowing. Run with -race.
func TestDuplex_ParallelSendersOneReader(t *testing.T) {
	t.Parallel()
	const (
		senders = 16
		perSend = 25
		maxTPDU = 128 // force multi-segment TSDUs
	)
	for _, transport := range []string{"pipe", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			var cli, srv *Conn
			if transport == "pipe" {
				cli, srv = openPipePair(t, maxTPDU, DefaultMaxTSDULength)
			} else {
				cli, srv = openTCPConnPair(t, maxTPDU, DefaultMaxTSDULength)
			}

			receive := func(c *Conn, want int) <-chan error {
				done := make(chan error, 1)
				go func() {
					next := make(map[int]int)
					for i := 0; i < want; i++ {
						b, err := c.ReadTSDU(context.Background())
						if err != nil {
							done <- fmt.Errorf("ReadTSDU %d: %w", i, err)
							return
						}
						s, q, err := checkTagged(b)
						if err != nil {
							done <- err
							return
						}
						if q != next[s] {
							done <- fmt.Errorf("sender %d: seq %d, want %d", s, q, next[s])
							return
						}
						next[s]++
					}
					done <- nil
				}()
				return done
			}
			send := func(c *Conn) <-chan error {
				done := make(chan error, 1)
				var wg sync.WaitGroup
				var failed atomic.Value
				for s := 0; s < senders; s++ {
					wg.Add(1)
					go func(s int) {
						defer wg.Done()
						rng := rand.New(rand.NewSource(int64(s)))
						for q := 0; q < perSend; q++ {
							ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
							err := c.WriteTSDU(ctx, encodeTagged(s, q, 1+rng.Intn(600)))
							cancel()
							if err != nil {
								failed.Store(fmt.Errorf("sender %d seq %d: %w", s, q, err))
								return
							}
						}
					}(s)
				}
				go func() {
					wg.Wait()
					if v := failed.Load(); v != nil {
						done <- v.(error)
						return
					}
					done <- nil
				}()
				return done
			}

			total := senders * perSend
			srvRecv, cliRecv := receive(srv, total), receive(cli, total)
			cliSend, srvSend := send(cli), send(srv)
			for _, ch := range []<-chan error{cliSend, srvSend, srvRecv, cliRecv} {
				select {
				case err := <-ch:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(30 * time.Second):
					t.Fatal("timeout")
				}
			}
		})
	}
}

// chaosConn splits writes into short writes (returning n < len with a nil
// error, which tpkt retries), returns short reads, adds jitter, and can reset
// the stream at a random point.
type chaosConn struct {
	net.Conn
	mu       sync.Mutex
	rng      *rand.Rand
	resetAt  int64 // total octets after which the stream is reset; 0 = never
	moved    int64
	maxChunk int
}

func (c *chaosConn) roll(n int) (chunk int, jitter time.Duration, reset bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	chunk = 1 + c.rng.Intn(c.maxChunk)
	if chunk > n {
		chunk = n
	}
	if c.rng.Intn(8) == 0 {
		jitter = time.Duration(c.rng.Intn(300)) * time.Microsecond
	}
	c.moved += int64(chunk)
	reset = c.resetAt > 0 && c.moved >= c.resetAt
	return chunk, jitter, reset
}

func (c *chaosConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	chunk, jitter, reset := c.roll(len(p))
	if reset {
		_ = c.Close()
	}
	time.Sleep(jitter)
	return c.Conn.Read(p[:chunk])
}

func (c *chaosConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	chunk, jitter, reset := c.roll(len(p))
	if reset {
		_ = c.Close()
	}
	time.Sleep(jitter)
	return c.Conn.Write(p[:chunk])
}

func openChaosPair(t *testing.T, seed int64, resetAt int64) (client, server *Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	cc := &chaosConn{Conn: c1, rng: rand.New(rand.NewSource(seed)), maxChunk: 7, resetAt: resetAt}
	sc := &chaosConn{Conn: c2, rng: rand.New(rand.NewSource(seed + 1)), maxChunk: 11}
	errCh := make(chan error, 1)
	go func() {
		var err error
		server, err = Accept(context.Background(), sc, ServerConfig{MaxTPDULength: 128})
		errCh <- err
	}()
	client, err := Connect(context.Background(), cc, ClientConfig{MaxTPDULength: 128})
	if aerr := <-errCh; err != nil || aerr != nil {
		if resetAt > 0 {
			t.Skipf("reset during handshake (seed %d)", seed)
		}
		t.Fatalf("handshake: %v / %v", err, aerr)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// chaosSeeds is the number of seeds of a chaos test: def, or the value of
// COTP_CHAOS_SEEDS, which the nightly workflow raises.
func chaosSeeds(def int64) int64 {
	if n, err := strconv.ParseInt(os.Getenv("COTP_CHAOS_SEEDS"), 10, 64); err == nil && n > 0 {
		return n
	}
	return def
}

// Partial writes, short reads, and jitter never corrupt or interleave TSDUs.
func TestDuplex_ChaosPartialIO(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= chaosSeeds(4); seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			t.Parallel()
			cli, srv := openChaosPair(t, seed, 0)
			const senders, perSend = 4, 10
			var wg sync.WaitGroup
			for s := 0; s < senders; s++ {
				wg.Add(1)
				go func(s int) {
					defer wg.Done()
					for q := 0; q < perSend; q++ {
						if err := cli.WriteTSDU(context.Background(), encodeTagged(s, q, 1+(s*q*37)%400)); err != nil {
							t.Errorf("WriteTSDU: %v", err)
							return
						}
					}
				}(s)
			}
			echo := make(chan error, 1)
			go func() {
				for i := 0; i < senders*perSend; i++ {
					b, err := srv.ReadTSDU(context.Background())
					if err != nil {
						echo <- err
						return
					}
					if _, _, err := checkTagged(b); err != nil {
						echo <- err
						return
					}
					if err := srv.WriteTSDU(context.Background(), b); err != nil {
						echo <- err
						return
					}
				}
				echo <- nil
			}()
			for i := 0; i < senders*perSend; i++ {
				b, err := cli.ReadTSDU(context.Background())
				if err != nil {
					t.Fatalf("ReadTSDU: %v", err)
				}
				if _, _, err := checkTagged(b); err != nil {
					t.Fatal(err)
				}
			}
			wg.Wait()
			if err := <-echo; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A reset at a random point ends every blocked operation on both sides with a
// classified error: no hang, no panic, no corrupted TSDU delivered.
func TestDuplex_ChaosReset(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= chaosSeeds(8); seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			t.Parallel()
			cli, srv := openChaosPair(t, seed, 200+seed*97)
			var wg sync.WaitGroup
			run := func(f func() error) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						if err := f(); err != nil {
							if !errors.Is(err, ErrClosed) && !errors.Is(err, ErrDisconnected) {
								t.Errorf("unclassified error: %v", err)
							}
							return
						}
					}
				}()
			}
			for _, c := range []*Conn{cli, srv} {
				c := c
				run(func() error {
					b, err := c.ReadTSDU(context.Background())
					if err == nil {
						if _, _, cerr := checkTagged(b); cerr != nil {
							t.Errorf("corrupt TSDU delivered: %v", cerr)
						}
					}
					return err
				})
				for s := 0; s < 3; s++ {
					s, q := s, 0
					run(func() error {
						q++
						return c.WriteTSDU(context.Background(), encodeTagged(s, q, 1+q*13%300))
					})
				}
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				// The reset closes the client side; the server must follow.
				t.Fatal("operations did not end after reset")
			}
		})
	}
}

// FuzzSegmentedRoundTrip sends a fuzz-chosen TSDU over a fuzz-chosen chunking
// of the stream and checks it arrives intact.
func FuzzSegmentedRoundTrip(f *testing.F) {
	f.Add([]byte("hello"), int64(1), uint8(3))
	f.Add(bytes.Repeat([]byte{0xAA}, 700), int64(7), uint8(1))
	f.Fuzz(func(t *testing.T, tsdu []byte, seed int64, maxChunk uint8) {
		if len(tsdu) == 0 || len(tsdu) > 4096 {
			t.Skip()
		}
		c1, c2 := net.Pipe()
		mc := int(maxChunk%32) + 1
		cc := &chaosConn{Conn: c1, rng: rand.New(rand.NewSource(seed)), maxChunk: mc}
		sc := &chaosConn{Conn: c2, rng: rand.New(rand.NewSource(seed ^ 0x5a)), maxChunk: mc}
		var srv *Conn
		errCh := make(chan error, 1)
		go func() {
			var err error
			srv, err = Accept(context.Background(), sc, ServerConfig{MaxTPDULength: 128})
			errCh <- err
		}()
		cli, err := Connect(context.Background(), cc, ClientConfig{MaxTPDULength: 128})
		if aerr := <-errCh; err != nil || aerr != nil {
			t.Fatalf("handshake: %v / %v", err, aerr)
		}
		defer func() { _ = cli.Close(); _ = srv.Close() }()
		reads := goRead(srv, context.Background())
		if err := cli.WriteTSDU(context.Background(), tsdu); err != nil {
			t.Fatal(err)
		}
		r := <-reads
		if r.err != nil || !bytes.Equal(r.b, tsdu) {
			t.Fatalf("round trip: %v (len %d vs %d)", r.err, len(r.b), len(tsdu))
		}
	})
}
