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
		TPDUSize:        uint8Ptr(0x0A),
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
		TPDUSize:        uint8Ptr(0x0A),
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

func BenchmarkTSDUSingleSegment(b *testing.B) {
	cli, srv := openPipePairBench(b, 1024, DefaultMaxTSDULength)
	payload := []byte("benchmark-single-segment")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		errCh := make(chan error, 1)
		go func() {
			_, err := srv.ReadTSDU(context.Background())
			errCh <- err
		}()
		if err := cli.WriteTSDU(context.Background(), payload); err != nil {
			b.Fatal(err)
		}
		if err := <-errCh; err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTSDUSegmented64KiB(b *testing.B) {
	benchmarkSegmentedTSDU(b, 64*1024)
}

func BenchmarkTSDUSegmented1MiB(b *testing.B) {
	benchmarkSegmentedTSDU(b, 1<<20)
}

func benchmarkSegmentedTSDU(b *testing.B, size int) {
	b.Helper()
	cli, srv := openPipePairBench(b, 128, size+1024)
	payload := bytes.Repeat([]byte{0x5A}, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		errCh := make(chan error, 1)
		go func() {
			got, err := srv.ReadTSDU(context.Background())
			if err != nil {
				errCh <- err
				return
			}
			if len(got) != size {
				errCh <- errBenchLen
				return
			}
			errCh <- nil
		}()
		if err := cli.WriteTSDU(context.Background(), payload); err != nil {
			b.Fatal(err)
		}
		if err := <-errCh; err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTSDUConcurrentRequestResponse(b *testing.B) {
	cli, srv := openPipePairBench(b, 1024, DefaultMaxTSDULength)
	req := []byte("ping")
	resp := []byte("pong")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		errCh := make(chan error, 1)
		go func() {
			got, err := srv.ReadTSDU(context.Background())
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(got, req) {
				errCh <- errBenchLen
				return
			}
			errCh <- srv.WriteTSDU(context.Background(), resp)
		}()
		clientRead := make(chan error, 1)
		go func() {
			got, err := cli.ReadTSDU(context.Background())
			if err != nil {
				clientRead <- err
				return
			}
			if !bytes.Equal(got, resp) {
				clientRead <- errBenchLen
				return
			}
			clientRead <- nil
		}()
		if err := cli.WriteTSDU(context.Background(), req); err != nil {
			b.Fatal(err)
		}
		if err := <-errCh; err != nil {
			b.Fatal(err)
		}
		if err := <-clientRead; err != nil {
			b.Fatal(err)
		}
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
