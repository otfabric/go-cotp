// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-tpkt"
)

// corruptFrame is one octet string the raw peer writes after the handshake:
// a TPKT packet (tpdu) or, when raw is set, octets written to the stream
// without TPKT framing.
type corruptFrame struct {
	tpdu []byte
	raw  bool
}

// buildCorruptStream segments tsdus into DT TPDUs and corrupts some of them
// (bit flips, truncation, extension, garbage outside TPKT). It returns the
// frames and the index of the first TSDU that a corrupted frame belongs to:
// every TSDU before it must be delivered intact.
func buildCorruptStream(rng *rand.Rand, tsdus [][]byte) ([]corruptFrame, int) {
	var frames []corruptFrame
	firstBad := len(tsdus)
	for i, tsdu := range tsdus {
		for off := 0; off < len(tsdu); {
			n := 1 + rng.Intn(64)
			if off+n > len(tsdu) {
				n = len(tsdu) - off
			}
			dt := &DT{EOT: off+n == len(tsdu), UserData: tsdu[off : off+n]}
			b, _ := dt.MarshalBinary()
			f := corruptFrame{tpdu: b}
			if rng.Intn(25) == 0 {
				switch rng.Intn(4) {
				case 0: // flip one to three octets anywhere, header included
					for k := 0; k <= rng.Intn(3); k++ {
						b[rng.Intn(len(b))] ^= byte(1 + rng.Intn(255))
					}
				case 1: // truncate inside the header
					f.tpdu = b[:rng.Intn(3)]
				case 2: // trailing garbage beyond the segment
					f.tpdu = append(b, byte(rng.Intn(256)))
					f.tpdu[0] = byte(rng.Intn(256))
				default: // octets outside TPKT framing
					g := make([]byte, 1+rng.Intn(8))
					rng.Read(g)
					f = corruptFrame{tpdu: g, raw: true}
				}
				if i < firstBad {
					firstBad = i
				}
			}
			frames = append(frames, f)
			off += n
		}
	}
	return frames, firstBad
}

// acceptRawPeer runs Accept against a raw TPKT peer that sends a Class 0 CR
// and reads the CC.
func acceptRawPeer(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	errCh := make(chan error, 1)
	var srv *Conn
	go func() {
		var err error
		srv, err = Accept(context.Background(), c2, ServerConfig{MaxTPDULength: 1024, MaxTSDULength: 1 << 16})
		errCh <- err
	}()
	size := uint8(0x0A)
	cr, err := (&CR{SourceRef: 0x2222, TPDUSize: &size}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	w, _ := tpkt.NewWriter(c1)
	if err := w.WritePacket(cr); err != nil {
		t.Fatal(err)
	}
	r, _ := tpkt.NewReader(c1, tpkt.ReaderConfig{})
	if _, err := r.ReadPacket(); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = c1.Close()
	})
	return srv, c1
}

// A peer that corrupts the open-state stream at random points: every TSDU
// before the first corruption arrives intact, the reader then ends with an
// error (never a panic or a hang), and the connection stays failed.
func TestChaos_CorruptedOpenStream(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= chaosSeeds(16); seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewSource(seed))
			tsdus := make([][]byte, 40)
			for i := range tsdus {
				tsdus[i] = make([]byte, 1+rng.Intn(600))
				rng.Read(tsdus[i])
			}
			frames, firstBad := buildCorruptStream(rng, tsdus)
			srv, peer := acceptRawPeer(t)

			go func() {
				defer peer.Close()
				w, _ := tpkt.NewWriter(peer)
				for _, f := range frames {
					var err error
					if f.raw {
						_, err = peer.Write(f.tpdu)
					} else {
						err = w.WritePacket(f.tpdu)
					}
					if err != nil {
						return
					}
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var readErr error
			for i := 0; ; i++ {
				b, err := srv.ReadTSDU(ctx)
				if err != nil {
					readErr = err
					break
				}
				if i < firstBad && !bytes.Equal(b, tsdus[i]) {
					t.Fatalf("TSDU %d changed before the first corruption (%d)", i, firstBad)
				}
			}
			if errors.Is(readErr, context.DeadlineExceeded) {
				t.Fatal("reader hung on a corrupted stream")
			}
			if !classifiedOpenErr(readErr) {
				t.Fatalf("unclassified error: %v", readErr)
			}
			if firstBad == len(tsdus) {
				// No corruption: the peer's close ends the stream.
				if !errors.Is(readErr, ErrDisconnected) && !errors.Is(readErr, ErrClosed) {
					t.Fatalf("clean stream ended with %v", readErr)
				}
				return
			}
			if err := srv.WriteTSDU(context.Background(), []byte{1}); err == nil {
				t.Fatalf("write succeeded after read failure %v", readErr)
			}
			if _, err := srv.ReadTSDU(context.Background()); err == nil {
				t.Fatalf("read succeeded after read failure %v", readErr)
			}
		})
	}
}

// classifiedOpenErr reports whether err carries a go-cotp sentinel a caller
// can switch on.
func classifiedOpenErr(err error) bool {
	for _, s := range []error{ErrHandshake, ErrUnexpectedTPDU, ErrDisconnected, ErrIncompleteTSDU, ErrTSDUTooLarge, ErrClosed} {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

// A TPKT framing violation (bad version, invalid length) is a peer protocol
// error: it matches ErrHandshake and keeps the go-tpkt sentinel, at a TSDU
// boundary and mid-TSDU alike.
func TestFramingErrorClassification(t *testing.T) {
	badVersion := []byte{0x04, 0x00, 0x00, 0x08, 0x02, 0xF0, 0x80, 0x01}
	shortLen := []byte{0x03, 0x00, 0x00, 0x02}
	cases := []struct {
		name string
		wire []byte
		mid  bool
		tpkt error
	}{
		{"version-boundary", badVersion, false, tpkt.ErrInvalidVersion},
		{"version-mid", badVersion, true, tpkt.ErrInvalidVersion},
		{"length-boundary", shortLen, false, tpkt.ErrInvalidPacketLength},
		{"length-mid", shortLen, true, tpkt.ErrInvalidPacketLength},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, peer := acceptRawPeer(t)
			go func() {
				if tc.mid {
					w, _ := tpkt.NewWriter(peer)
					first, _ := (&DT{UserData: []byte{1, 2, 3}}).MarshalBinary()
					if w.WritePacket(first) != nil {
						return
					}
				}
				_, _ = peer.Write(tc.wire)
			}()
			_, err := srv.ReadTSDU(context.Background())
			if !errors.Is(err, ErrHandshake) || !errors.Is(err, tc.tpkt) {
				t.Fatalf("err = %v; want ErrHandshake and %v", err, tc.tpkt)
			}
			if errors.Is(err, ErrIncompleteTSDU) != tc.mid {
				t.Fatalf("err = %v; ErrIncompleteTSDU match must be %v", err, tc.mid)
			}
			if errors.Is(err, ErrDisconnected) {
				t.Fatalf("framing violation reported as disconnect: %v", err)
			}
			if werr := srv.WriteTSDU(context.Background(), []byte{1}); werr == nil {
				t.Fatal("write succeeded after framing violation")
			}
		})
	}
}

func TestFramingErrorDuringHandshake(t *testing.T) {
	t.Run("connect", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c2.Close()
		go func() {
			r, _ := tpkt.NewReader(c2, tpkt.ReaderConfig{})
			if _, err := r.ReadPacket(); err != nil {
				return
			}
			_, _ = c2.Write([]byte{0x05, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0, 0, 0, 0, 0})
		}()
		_, err := Connect(context.Background(), c1, ClientConfig{})
		if !errors.Is(err, ErrHandshake) || !errors.Is(err, tpkt.ErrInvalidVersion) {
			t.Fatalf("err = %v; want ErrHandshake and tpkt.ErrInvalidVersion", err)
		}
	})
	t.Run("accept", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go func() { _, _ = c1.Write([]byte{0x03, 0x00, 0x00, 0x02}) }()
		_, err := Accept(context.Background(), c2, ServerConfig{})
		if !errors.Is(err, ErrHandshake) || !errors.Is(err, tpkt.ErrInvalidPacketLength) {
			t.Fatalf("err = %v; want ErrHandshake and tpkt.ErrInvalidPacketLength", err)
		}
	})
}
