// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-tpkt"
)

// openPipePair completes a CR/CC handshake over net.Pipe and returns open Conns.
func openPipePair(t *testing.T, maxTPDU, maxTSDU int) (client, server *Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	errCh := make(chan error, 1)
	var srv *Conn
	go func() {
		var err error
		srv, err = Accept(context.Background(), c2, ServerConfig{
			MaxTPDULength: maxTPDU,
			MaxTSDULength: maxTSDU,
		})
		errCh <- err
	}()
	cli, err := Connect(context.Background(), c1, ClientConfig{
		MaxTPDULength: maxTPDU,
		MaxTSDULength: maxTSDU,
	})
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

func TestTSDU_OneDTRoundTrip(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	errCh := make(chan error, 1)
	var got []byte
	go func() {
		var err error
		got, err = srv.ReadTSDU(context.Background())
		errCh <- err
	}()
	if err := cli.WriteTSDU(context.Background(), want); err != nil {
		t.Fatalf("WriteTSDU: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("ReadTSDU: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestTSDU_FullDuplexConcurrent(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	a := []byte("client-to-server")
	b := []byte("server-to-client")

	var wg sync.WaitGroup
	wg.Add(4)
	errCh := make(chan error, 4)

	go func() {
		defer wg.Done()
		errCh <- cli.WriteTSDU(context.Background(), a)
	}()
	go func() {
		defer wg.Done()
		errCh <- srv.WriteTSDU(context.Background(), b)
	}()
	go func() {
		defer wg.Done()
		got, err := srv.ReadTSDU(context.Background())
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(got, a) {
			errCh <- fmt.Errorf("server read %x", got)
			return
		}
		errCh <- nil
	}()
	go func() {
		defer wg.Done()
		got, err := cli.ReadTSDU(context.Background())
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(got, b) {
			errCh <- fmt.Errorf("client read %x", got)
			return
		}
		errCh <- nil
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestTSDU_EmptyWriteRejectedNoIO(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	readStarted := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		close(readStarted)
		_, err := srv.ReadTSDU(context.Background())
		errCh <- err
	}()
	<-readStarted
	time.Sleep(20 * time.Millisecond)

	if err := cli.WriteTSDU(context.Background(), nil); !errors.Is(err, ErrEmptyTSDU) {
		t.Fatalf("err = %v, want ErrEmptyTSDU", err)
	}
	if err := cli.WriteTSDU(context.Background(), []byte{}); !errors.Is(err, ErrEmptyTSDU) {
		t.Fatalf("err = %v, want ErrEmptyTSDU", err)
	}

	// Peer still blocked waiting — no bytes were emitted. Unblock via Close.
	_ = cli.Close()
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) && !errors.Is(err, ErrDisconnected) {
			// Server sees peer close as disconnect; either is fine for "no empty DT sent".
			if err == nil {
				t.Fatal("unexpected successful read of empty write")
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadTSDU not unblocked")
	}
}

func TestTSDU_WriteExceedsMaxTSDUNoIO(t *testing.T) {
	cli, _ := openPipePair(t, 1024, 16)
	err := cli.WriteTSDU(context.Background(), make([]byte, 17))
	if !errors.Is(err, ErrTSDUTooLarge) {
		t.Fatalf("err = %v, want ErrTSDUTooLarge", err)
	}
	if cli.terminalKind() != terminalNone {
		t.Fatal("oversized write must not abort the connection")
	}
}

func TestTSDU_ValidMinimalEOT1(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}
	go func() { _ = cli.WriteTSDU(context.Background(), payload) }()
	got, err := srv.ReadTSDU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("len got=%d want=%d", len(got), len(payload))
	}
}

func TestTSDU_EOFAfterNonEOTIsIncomplete(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		raw := []byte{0x02, 0xF0, 0x00, 0xAA} // EOT=0, productive segment
		_ = writeRawTPKT(cli.raw, raw)
		_ = cli.raw.Close()
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrIncompleteTSDU) || !errors.Is(err, ErrDisconnected) || !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want Incomplete+Disconnected+EOF", err)
	}
}

func TestTSDU_EmptySegmentRejected(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		// LI=2, EOT=1, zero user data.
		_ = writeRawTPKT(cli.raw, []byte{0x02, 0xF0, 0x80})
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestTSDU_F1Rejected(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		raw := []byte{0x02, 0xF1, 0x80, 0xAA}
		_ = writeRawTPKT(cli.raw, raw)
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestTSDU_NonZeroTPDUNRRejected(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		raw := []byte{0x02, 0xF0, 0x81, 0xAA} // EOT=1, NR=1
		_ = writeRawTPKT(cli.raw, raw)
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestTSDU_NonDTAborts(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DR{DestinationRef: 1, SourceRef: 2, Reason: 0}))
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrUnexpectedTPDU) {
		t.Fatalf("err = %v, want ErrUnexpectedTPDU", err)
	}
	var u *UnexpectedTPDUError
	if !errors.As(err, &u) || u.Phase != PhaseDataTransfer {
		t.Fatalf("UnexpectedTPDUError = %#v", u)
	}
}

func TestTSDU_MalformedDTAborts(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		_ = writeRawTPKT(cli.raw, []byte{0x02, 0x00, 0x00}) // not a DT
	}()
	_, err := srv.ReadTSDU(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if srv.terminalKind() != terminalAborted {
		t.Fatal("want aborted")
	}
}

func TestTSDU_InboundExceedsNegotiatedMax(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
	go func() {
		// TPDU length 129 > negotiated 128.
		user := make([]byte, 126) // 3+126=129
		dt := &DT{EOT: true, UserData: user}
		b, _ := dt.MarshalBinary()
		_ = writeRawTPKT(cli.raw, b)
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestTSDU_InboundExceedsMaxTSDU(t *testing.T) {
	cli, srv := openPipePair(t, 1024, 8)
	go func() {
		_ = cli.writer.WritePacket(mustMarshal(t, &DT{EOT: true, UserData: make([]byte, 9)}))
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrTSDUTooLarge) {
		t.Fatalf("err = %v, want ErrTSDUTooLarge", err)
	}
}

func TestTSDU_ReturnedDataDoesNotAlias(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() { _ = cli.WriteTSDU(context.Background(), []byte{1, 2, 3}) }()
	got, err := srv.ReadTSDU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got[0] = 0xFF
	got2, err := func() ([]byte, error) {
		// Second write/read to ensure first buffer mutation didn't corrupt internals.
		go func() { _ = cli.WriteTSDU(context.Background(), []byte{1, 2, 3}) }()
		return srv.ReadTSDU(context.Background())
	}()
	if err != nil {
		t.Fatal(err)
	}
	if got2[0] != 1 {
		t.Fatalf("aliasing detected: second read %v", got2)
	}
}

func TestTSDU_PeerEOF(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	_ = cli.raw.Close()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrDisconnected) || !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want ErrDisconnected+EOF", err)
	}
}

func TestTSDU_LocalCloseUnblocksRead(t *testing.T) {
	_, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	errCh := make(chan error, 1)
	go func() {
		_, err := srv.ReadTSDU(context.Background())
		errCh <- err
	}()
	time.Sleep(30 * time.Millisecond)
	if err := srv.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("ReadTSDU after Close: %v, want ErrClosed", err)
		}
		if errors.Is(err, ErrDisconnected) {
			t.Fatal("local Close must not classify as ErrDisconnected")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadTSDU not unblocked")
	}
}

func TestTSDU_ContextTimeoutAfterIOAborts(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := srv.ReadTSDU(ctx)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			// deadline from armDeadline / timeout
			t.Logf("err = %v (acceptable if wrapped as ErrClosed from deadline)", err)
		}
		if srv.terminalKind() == terminalNone {
			t.Fatal("connection must be aborted after I/O-started timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadTSDU did not return")
	}
	_ = cli.Close()
}

func TestTSDU_FirstTerminalCauseStable(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	_ = cli.raw.Close()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrDisconnected) {
		t.Fatalf("err = %v", err)
	}
	if err2 := srv.Close(); !errors.Is(err2, ErrDisconnected) {
		t.Fatalf("Close after disconnect: %v, want first cause", err2)
	}
	err3 := srv.WriteTSDU(context.Background(), []byte{1})
	if !errors.Is(err3, ErrDisconnected) {
		t.Fatalf("WriteTSDU after disconnect: %v", err3)
	}
}

func writeRawTPKT(c net.Conn, payload []byte) error {
	w, err := tpkt.NewWriter(c)
	if err != nil {
		return err
	}
	return w.WritePacket(payload)
}

func TestTSDU_SegmentSizes128(t *testing.T) {
	const maxTPDU = 128
	const maxSeg = 125 // 128 - 3
	cases := []struct {
		name     string
		n        int
		segments int
	}{
		{"1 byte", 1, 1},
		{"exact one segment", maxSeg, 1},
		{"one over → two", maxSeg + 1, 2},
		{"two full", maxSeg * 2, 2},
		{"two full + 1", maxSeg*2 + 1, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := openPipePair(t, maxTPDU, DefaultMaxTSDULength)
			want := bytes.Repeat([]byte{0x5A}, tc.n)

			wire, restore := captureWrites(t, cli)
			defer restore()

			errCh := make(chan error, 1)
			var got []byte
			go func() {
				var err error
				got, err = srv.ReadTSDU(context.Background())
				errCh <- err
			}()
			if err := cli.WriteTSDU(context.Background(), want); err != nil {
				t.Fatalf("WriteTSDU: %v", err)
			}
			if err := <-errCh; err != nil {
				t.Fatalf("ReadTSDU: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("reassembled len=%d want=%d", len(got), len(want))
			}
			pkts := wire.packets()
			if len(pkts) != tc.segments {
				t.Fatalf("segment count = %d, want %d", len(pkts), tc.segments)
			}
			var rebuilt []byte
			for i, p := range pkts {
				if len(p) > maxTPDU {
					t.Fatalf("TPDU len %d > negotiated %d", len(p), maxTPDU)
				}
				d, err := Decode(p)
				if err != nil || d.DT == nil {
					t.Fatalf("segment %d: %v", i, err)
				}
				if d.DT.EOT != (i == len(pkts)-1) {
					t.Fatalf("segment %d EOT=%v, want final-only", i, d.DT.EOT)
				}
				rebuilt = append(rebuilt, d.DT.UserData...)
			}
			if !bytes.Equal(rebuilt, want) {
				t.Fatal("wire user data does not recombine to TSDU")
			}
		})
	}
}

func TestTSDU_ExactMaxTSDULength(t *testing.T) {
	const maxTSDU = 300
	cli, srv := openPipePair(t, 128, maxTSDU)
	want := bytes.Repeat([]byte{0x11}, maxTSDU)
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
		t.Fatalf("len=%d", len(got))
	}
}

func TestTSDU_OneAboveMaxTSDURejectedBeforeWrite(t *testing.T) {
	cli, _ := openPipePair(t, 128, 300)
	wire, restore := captureWrites(t, cli)
	defer restore()
	err := cli.WriteTSDU(context.Background(), make([]byte, 301))
	if !errors.Is(err, ErrTSDUTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if len(wire.packets()) != 0 {
		t.Fatal("expected no protocol I/O")
	}
}

func TestTSDU_S7Like1024Segmentation(t *testing.T) {
	const maxTPDU = 1024
	const maxSeg = 1021
	cli, srv := openPipePair(t, maxTPDU, DefaultMaxTSDULength)
	want := bytes.Repeat([]byte{0x7E}, maxSeg+1) // two segments

	wire, restore := captureWrites(t, cli)
	defer restore()

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
		t.Fatal("mismatch")
	}
	pkts := wire.packets()
	if len(pkts) != 2 {
		t.Fatalf("segments = %d, want 2", len(pkts))
	}
	for _, p := range pkts {
		if len(p) > maxTPDU {
			t.Fatalf("TPDU len %d > %d", len(p), maxTPDU)
		}
	}
}

func TestTSDU_ReassembleTwoAndThreeSegments(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
	// Feed three segments manually: 125 + 125 + 1
	go func() {
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: false, UserData: bytes.Repeat([]byte{1}, 125)}))
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: false, UserData: bytes.Repeat([]byte{2}, 125)}))
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: true, UserData: []byte{3}}))
	}()
	got, err := srv.ReadTSDU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 251 || got[0] != 1 || got[125] != 2 || got[250] != 3 {
		t.Fatalf("bad reassembly: len=%d", len(got))
	}
}

func TestTSDU_CoalescedTPKTsInStream(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
	go func() {
		p1 := mustEncodeTPKT(t, mustMarshal(t, &DT{EOT: false, UserData: []byte{0xA1}}))
		p2 := mustEncodeTPKT(t, mustMarshal(t, &DT{EOT: true, UserData: []byte{0xA2}}))
		_, _ = cli.raw.Write(append(p1, p2...))
	}()
	got, err := srv.ReadTSDU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0xA1, 0xA2}) {
		t.Fatalf("got %x", got)
	}
}

func TestTSDU_FragmentedTCPReads(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
	go func() {
		pkt := mustEncodeTPKT(t, mustMarshal(t, &DT{EOT: true, UserData: []byte{0xB1, 0xB2, 0xB3}}))
		for _, b := range pkt {
			if _, err := cli.raw.Write([]byte{b}); err != nil {
				return
			}
		}
	}()
	got, err := srv.ReadTSDU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0xB1, 0xB2, 0xB3}) {
		t.Fatalf("got %x", got)
	}
}

func TestTSDU_NonEOTThenUnexpectedTPDU(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
	go func() {
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: false, UserData: []byte{1}}))
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DR{DestinationRef: 1, SourceRef: 2, Reason: 0}))
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrIncompleteTSDU) || !errors.Is(err, ErrUnexpectedTPDU) {
		t.Fatalf("err = %v, want Incomplete+Unexpected", err)
	}
}

func TestTSDU_ValidFirstMalformedSecond(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
	go func() {
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: false, UserData: []byte{1}}))
		_ = writeRawTPKT(cli.raw, []byte{0x02, 0x00, 0x00})
	}()
	_, err := srv.ReadTSDU(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if srv.terminalKind() != terminalAborted {
		t.Fatal("want aborted")
	}
}

func TestTSDU_ReassemblyBoundAbort(t *testing.T) {
	cli, srv := openPipePair(t, 128, 200)
	go func() {
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: false, UserData: bytes.Repeat([]byte{1}, 125)}))
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: true, UserData: bytes.Repeat([]byte{2}, 125)}))
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrTSDUTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestTSDU_LocalCloseMidReassembly(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
	errCh := make(chan error, 1)
	go func() {
		_, err := srv.ReadTSDU(context.Background())
		errCh <- err
	}()
	// Deliver one non-final segment, then close locally while waiting for more.
	_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: false, UserData: []byte{1}}))
	time.Sleep(30 * time.Millisecond)
	if err := srv.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
		if errors.Is(err, ErrDisconnected) {
			t.Fatal("local close must not be peer disconnect")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("not unblocked")
	}
}

// writeCapture records TPKT payloads written by a Conn.
type writeCapture struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (c *writeCapture) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.pkts))
	for i, p := range c.pkts {
		out[i] = append([]byte(nil), p...)
	}
	return out
}

func captureWrites(t *testing.T, conn *Conn) (*writeCapture, func()) {
	t.Helper()
	wc := &writeCapture{}
	oldWriter := conn.writer
	pr, pw := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = pr.Close() }()
		r, err := tpkt.NewReader(pr, tpkt.ReaderConfig{})
		if err != nil {
			return
		}
		for {
			p, err := r.ReadPacket()
			if err != nil {
				return
			}
			wc.mu.Lock()
			wc.pkts = append(wc.pkts, append([]byte(nil), p...))
			wc.mu.Unlock()
			if err := oldWriter.WritePacket(p); err != nil {
				return
			}
		}
	}()
	w, err := tpkt.NewWriter(pw)
	if err != nil {
		t.Fatal(err)
	}
	conn.writer = w
	return wc, func() {
		conn.writer = oldWriter
		_ = pw.Close()
		<-done
	}
}

func mustEncodeTPKT(t *testing.T, payload []byte) []byte {
	t.Helper()
	pkt, err := tpkt.EncodePacket(payload)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}
