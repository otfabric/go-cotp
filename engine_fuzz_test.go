// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-tpkt"
)

func FuzzDecodeSizeOffer(f *testing.F) {
	f.Add([]byte{0x0A}, []byte{})
	f.Add([]byte{0x0C}, []byte{})
	f.Add([]byte{}, []byte{0x00, 0x00, 0x00, 0x08})
	f.Add([]byte{0x0A}, []byte{0x00, 0x00, 0x00, 0x08})
	f.Add([]byte{0x07}, []byte{0x00, 0x00, 0x01, 0xFF})
	f.Fuzz(func(t *testing.T, stdRaw, prefRaw []byte) {
		var std *uint8
		if len(stdRaw) > 0 {
			v := stdRaw[0]
			std = &v
		}
		var pref *uint32
		if len(prefRaw) >= 4 {
			u := uint32(prefRaw[0])<<24 | uint32(prefRaw[1])<<16 | uint32(prefRaw[2])<<8 | uint32(prefRaw[3])
			pref = &u
		}
		offer, err := decodeSizeOffer(std, pref)
		if err != nil {
			return
		}
		sel, err := selectSize(offer, 2048, 0, SizeProfileRFC1006Compat)
		if err != nil {
			return
		}
		if sel.Effective > 2048 {
			t.Fatalf("effective %d exceeds local ceiling", sel.Effective)
		}
		if offer.Standard != nil && sel.Path == sizePathStandard && sel.Effective > *offer.Standard {
			t.Fatalf("selected %d > peer standard %d", sel.Effective, *offer.Standard)
		}
		if offer.Preferred != nil && sel.Path == sizePathPreferred && sel.Effective > *offer.Preferred {
			t.Fatalf("selected %d > peer preferred %d", sel.Effective, *offer.Preferred)
		}
	})
}

func FuzzDecodeOpenDT(f *testing.F) {
	f.Add([]byte{0x02, 0xF0, 0x80, 0x01}, 1024)
	f.Add([]byte{0x02, 0xF0, 0x00, 0x01}, 128)
	f.Add([]byte{0x02, 0xF1, 0x80, 0x01}, 1024)
	f.Add([]byte{0x02, 0xF0, 0x81, 0x01}, 1024)
	f.Add([]byte{0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}, 1024)
	f.Add(mustMarshalFuzz(&DT{EOT: true, UserData: bytes.Repeat([]byte{9}, 126)}), 128)
	f.Fuzz(func(t *testing.T, packet []byte, maxTPDU int) {
		if maxTPDU < 0 {
			maxTPDU = -maxTPDU
		}
		if maxTPDU > 1<<20 {
			maxTPDU %= 65532
		}
		dt, err := decodeOpenDT(packet, maxTPDU)
		if err != nil {
			return
		}
		if dt == nil {
			t.Fatal("nil DT without error")
		}
		if maxTPDU > 0 && len(packet) > maxTPDU {
			t.Fatal("accepted TPDU larger than negotiated max")
		}
	})
}

func FuzzAcceptHandshake(f *testing.F) {
	for _, s := range [][]byte{
		mustMarshalFuzz(&CR{SourceRef: 1, TPDUSize: uint8PtrFuzz(0x0A)}),
		mustMarshalFuzz(&CR{SourceRef: 0, TPDUSize: uint8PtrFuzz(0x0A)}),
		mustMarshalFuzz(&CR{DestinationRef: 1, SourceRef: 2, TPDUSize: uint8PtrFuzz(0x0A)}),
		mustMarshalFuzz(&CR{SourceRef: 3, ClassOption: 0x20, TPDUSize: uint8PtrFuzz(0x0A)}),
		mustMarshalFuzz(&CR{CDT: 1, SourceRef: 4, TPDUSize: uint8PtrFuzz(0x0A)}),
		mustMarshalFuzz(&CR{SourceRef: 5, TPDUSize: uint8PtrFuzz(0x0C)}),
		{0x02, 0x00, 0x00},
		loadHexSeed(f, "testdata/tp0/connect/s7_cr_tsap1024.hex"),
		loadHexSeed(f, "testdata/tp0/connect/mms_cr_selectors.hex"),
		loadHexSeed(f, "testdata/tp0/connect/preferred_max_cr.hex"),
	} {
		if len(s) > 0 {
			f.Add(s)
		}
	}
	f.Fuzz(func(t *testing.T, crPayload []byte) {
		if len(crPayload) == 0 || len(crPayload) > 2048 {
			return
		}
		before := defaultRefs.Len()
		c1, c2 := net.Pipe()
		defer func() { _ = c1.Close() }()
		defer func() { _ = c2.Close() }()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = writeRawTPKT(c1, padTPKTPayload(crPayload))
			r, err := tpkt.NewReader(c1, tpkt.ReaderConfig{})
			if err != nil {
				return
			}
			_, _ = r.ReadPacket()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		conn, err := Accept(ctx, c2, ServerConfig{MaxTPDULength: 1024})
		if err == nil {
			if conn == nil {
				t.Fatal("nil conn without error")
			}
			neg := conn.Negotiated()
			if neg.MaxTPDULength > 1024 || neg.MaxTPDULength < MinTPDULength {
				t.Fatalf("negotiated max %d out of range", neg.MaxTPDULength)
			}
			if neg.LocalRef == 0 || neg.RemoteRef == 0 {
				t.Fatalf("zero ref: %+v", neg)
			}
			local := neg.LocalRef
			_ = conn.Close()
			if defaultRefs.Active(local) {
				t.Fatal("ref still active after Close")
			}
			if err2 := conn.WriteTSDU(context.Background(), []byte{1}); err2 == nil {
				t.Fatal("WriteTSDU succeeded after Close")
			}
		} else if defaultRefs.Len() != before {
			t.Fatalf("ref leak on Accept failure: before=%d after=%d", before, defaultRefs.Len())
		}
		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			_ = c1.Close()
			<-done
		}
	})
}

func FuzzOpenStateDispatch(f *testing.F) {
	for _, s := range [][]byte{
		mustMarshalFuzz(&CR{SourceRef: 1}),
		mustMarshalFuzz(&CC{DestinationRef: 1, SourceRef: 2}),
		mustMarshalFuzz(&DR{DestinationRef: 1, SourceRef: 2}),
		mustMarshalFuzz(&ER{DestinationRef: 1}),
		mustMarshalFuzz(&DT{EOT: true, UserData: []byte{1}}),
		mustMarshalFuzz(&DT{EOT: false, UserData: []byte{1}}),
		{0x02, 0xF1, 0x80, 0x01},
		{0x02, 0xF0, 0x80},
		loadHexSeed(f, "testdata/tp0/data/dt_seg_non_eot.hex"),
		loadHexSeed(f, "testdata/tp0/data/dt_seg_eot.hex"),
	} {
		if len(s) > 0 {
			f.Add(s, true)
			f.Add(s, false)
		}
	}
	f.Fuzz(func(t *testing.T, payload []byte, eotFirst bool) {
		if len(payload) == 0 || len(payload) > 4096 {
			return
		}
		cli, srv := openPipePair(t, 128, 512)

		go func() {
			if eotFirst {
				_ = writeRawTPKT(cli.raw, padTPKTPayload(payload))
				return
			}
			_ = writeRawTPKT(cli.raw, mustMarshalFuzz(&DT{EOT: false, UserData: []byte{0x11}}))
			_ = writeRawTPKT(cli.raw, padTPKTPayload(payload))
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		tsdu, err := srv.ReadTSDU(ctx)
		if err == nil {
			if len(tsdu) > 512 {
				t.Fatalf("TSDU len %d > MaxTSDULength", len(tsdu))
			}
			return
		}
		err2 := srv.WriteTSDU(context.Background(), []byte{1})
		if err2 == nil {
			t.Fatal("WriteTSDU succeeded after failed ReadTSDU")
		}
		if srv.terminalKind() == terminalNone {
			t.Fatalf("not terminal after error: read=%v write=%v", err, err2)
		}
	})
}

func mustMarshalFuzz(v interface{ MarshalBinary() ([]byte, error) }) []byte {
	b, err := v.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func uint8PtrFuzz(v uint8) *uint8 { return &v }

func loadHexSeed(f *testing.F, path string) []byte {
	f.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(raw)), " ", ""))
	if err != nil {
		return nil
	}
	return b
}

func padTPKTPayload(b []byte) []byte {
	if len(b) >= 3 {
		return b
	}
	out := make([]byte, 3)
	copy(out, b)
	return out
}
