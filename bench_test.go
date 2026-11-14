// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
)

var errBenchLen = errors.New("benchmark length mismatch")

func BenchmarkCREncodeDecode(b *testing.B) {
	cr := &CR{
		SourceRef:       0x0001,
		CallingSelector: []byte{0x01, 0x00},
		CalledSelector:  []byte{0x01, 0x01},
		TPDUSize:        new(uint8(0x0A)),
	}
	wire, err := cr.MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := cr.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeCR(out); err != nil {
			b.Fatal(err)
		}
		_ = wire
	}
}

func BenchmarkCCEncodeDecode(b *testing.B) {
	cc := &CC{
		DestinationRef:  0x0001,
		SourceRef:       0x0002,
		CallingSelector: []byte{0x01, 0x00},
		CalledSelector:  []byte{0x01, 0x01},
		TPDUSize:        new(uint8(0x0A)),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := cc.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeCC(out); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPreferredSizeNegotiation(b *testing.B) {
	code := uint8(0x0A)
	units := uint32(8)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offer, err := decodeSizeOffer(&code, &units)
		if err != nil {
			b.Fatal(err)
		}
		sel, err := selectSize(offer, 1000, 0, SizeProfilePreferredMaximum)
		if err != nil {
			b.Fatal(err)
		}
		if sel.Effective != 896 {
			b.Fatalf("effective = %d", sel.Effective)
		}
	}
}

// The TSDU benchmarks below run two Conns of this package against each other
// over net.Pipe, a synchronous in-memory stream: every Write waits for the
// matching Read. They measure segmentation, TPKT framing, reassembly and the
// hand-over between the writing and the reading goroutine. No socket and no
// kernel is involved, so they are not throughput figures for TCP, and no
// figure from them is published (LIMITATIONS.md "Timing").
//
// The peer is one goroutine started before the timer: the timed loop holds
// the operations under measurement and nothing of the harness.

// drainTSDUs reads n TSDUs of size octets from c on one goroutine and reports
// the first failure, or nil once all n have arrived. On a failure it closes
// c, so a writer blocked on the pipe returns.
func drainTSDUs(c *Conn, n, size int) <-chan error {
	done := make(chan error, 1)
	go func() {
		for range n {
			got, err := c.ReadTSDU(context.Background())
			if err == nil && len(got) != size {
				err = errBenchLen
			}
			if err != nil {
				_ = c.Close()
				done <- err
				return
			}
		}
		done <- nil
	}()
	return done
}

// BenchmarkTSDUSingleSegment: one WriteTSDU of a 24-octet TSDU (a single DT)
// and the ReadTSDU that receives it, per iteration.
func BenchmarkTSDUSingleSegment(b *testing.B) {
	cli, srv := openPipePairBench(b, 1024, DefaultMaxTSDULength)
	payload := []byte("benchmark-single-segment")
	received := drainTSDUs(srv, b.N, len(payload))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := cli.WriteTSDU(context.Background(), payload); err != nil {
			b.Fatal(err)
		}
	}
	if err := <-received; err != nil {
		b.Fatal(err)
	}
}

// BenchmarkTSDUSegmented64KiB: one 64 KiB TSDU written as 525 DT segments of
// 125 octets (TPDU size 128) and reassembled, per iteration.
func BenchmarkTSDUSegmented64KiB(b *testing.B) {
	benchmarkSegmentedTSDU(b, 64*1024)
}

// BenchmarkTSDUSegmented1MiB: one 1 MiB TSDU written as 8389 DT segments of
// 125 octets (TPDU size 128) and reassembled, per iteration.
func BenchmarkTSDUSegmented1MiB(b *testing.B) {
	benchmarkSegmentedTSDU(b, 1<<20)
}

func benchmarkSegmentedTSDU(b *testing.B, size int) {
	b.Helper()
	cli, srv := openPipePairBench(b, 128, size+1024)
	payload := bytes.Repeat([]byte{0x5A}, size)
	received := drainTSDUs(srv, b.N, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := cli.WriteTSDU(context.Background(), payload); err != nil {
			b.Fatal(err)
		}
	}
	if err := <-received; err != nil {
		b.Fatal(err)
	}
}

// BenchmarkTSDUConcurrentRequestResponse: one request of 4 octets and its
// response of 4 octets per iteration, client and server each on its own
// goroutine. The name is kept for comparison with earlier runs; the exchange
// is sequential, one request at a time.
func BenchmarkTSDUConcurrentRequestResponse(b *testing.B) {
	cli, srv := openPipePairBench(b, 1024, DefaultMaxTSDULength)
	req := []byte("ping")
	resp := []byte("pong")

	// The server answers b.N requests on one goroutine.
	served := make(chan error, 1)
	go func() {
		for range b.N {
			got, err := srv.ReadTSDU(context.Background())
			if err == nil && !bytes.Equal(got, req) {
				err = errBenchLen
			}
			if err == nil {
				err = srv.WriteTSDU(context.Background(), resp)
			}
			if err != nil {
				_ = srv.Close()
				served <- err
				return
			}
		}
		served <- nil
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := cli.WriteTSDU(context.Background(), req); err != nil {
			b.Fatal(err)
		}
		got, err := cli.ReadTSDU(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(got, resp) {
			b.Fatal(errBenchLen)
		}
	}
	if err := <-served; err != nil {
		b.Fatal(err)
	}
}

func openPipePairBench(b *testing.B, maxTPDU, maxTSDU int) (client, server *Conn) {
	b.Helper()
	c1, c2 := net.Pipe()
	errCh := make(chan error, 1)
	var srv *Conn
	go func() {
		var err error
		srv, err = Accept(context.Background(), c2, ServerConfig{MaxTPDULength: maxTPDU, MaxTSDULength: maxTSDU})
		errCh <- err
	}()
	cli, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: maxTPDU, MaxTSDULength: maxTSDU})
	if err != nil {
		b.Fatal(err)
	}
	if err := <-errCh; err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
	})
	return cli, srv
}
