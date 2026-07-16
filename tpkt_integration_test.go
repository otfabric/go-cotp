// SPDX-License-Identifier: MIT

package cotp_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/otfabric/go-cotp"
	"github.com/otfabric/go-tpkt"
)

func TestTpktWriteReadDecodeRoundTrip(t *testing.T) {
	cr := &cotp.CR{
		CDT:            0,
		DestinationRef: 0,
		SourceRef:      0x1234,
		ClassOption:    0,
	}
	encoded, err := cr.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	var buf bytes.Buffer
	w, err := tpkt.NewWriter(&buf)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WritePacket(encoded); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	r, err := tpkt.NewReader(&buf, tpkt.ReaderConfig{})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	payload, err := r.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if !bytes.Equal(payload, encoded) {
		t.Fatalf("ReadPacket payload mismatch:\n got %x\nwant %x", payload, encoded)
	}

	msg, err := cotp.Decode(payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if msg.Type != cotp.TypeCR || msg.CR == nil {
		t.Fatalf("expected CR, got Type=%v CR=%v", msg.Type, msg.CR != nil)
	}
	if msg.CR.SourceRef != 0x1234 {
		t.Errorf("SourceRef = %#x, want 0x1234", msg.CR.SourceRef)
	}
}

func TestTpktMultiplePacketsPreserveTPDUBoundaries(t *testing.T) {
	types := []struct {
		name string
		enc  func() ([]byte, error)
		want cotp.TPDUType
	}{
		{
			name: "CR",
			enc: func() ([]byte, error) {
				return (&cotp.CR{SourceRef: 1}).MarshalBinary()
			},
			want: cotp.TypeCR,
		},
		{
			name: "CC",
			enc: func() ([]byte, error) {
				return (&cotp.CC{DestinationRef: 1, SourceRef: 2}).MarshalBinary()
			},
			want: cotp.TypeCC,
		},
		{
			name: "DT",
			enc: func() ([]byte, error) {
				return (&cotp.DT{UserData: []byte{0xAA, 0xBB}}).MarshalBinary()
			},
			want: cotp.TypeDT,
		},
		{
			name: "DR",
			enc: func() ([]byte, error) {
				return (&cotp.DR{DestinationRef: 1, SourceRef: 2, Reason: 0}).MarshalBinary()
			},
			want: cotp.TypeDR,
		},
		{
			name: "ED",
			enc: func() ([]byte, error) {
				dst := uint16(1)
				nr := uint8(0)
				return (&cotp.ED{DestinationRef: &dst, TPDUNR: &nr, UserData: []byte{0x01}}).MarshalBinary()
			},
			want: cotp.TypeED,
		},
	}

	var buf bytes.Buffer
	w, err := tpkt.NewWriter(&buf)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	var encoded [][]byte
	for _, tc := range types {
		b, err := tc.enc()
		if err != nil {
			t.Fatalf("%s MarshalBinary: %v", tc.name, err)
		}
		encoded = append(encoded, b)
		if err := w.WritePacket(b); err != nil {
			t.Fatalf("WritePacket %s: %v", tc.name, err)
		}
	}

	r, err := tpkt.NewReader(&buf, tpkt.ReaderConfig{})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	for i, tc := range types {
		payload, err := r.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket %s: %v", tc.name, err)
		}
		if !bytes.Equal(payload, encoded[i]) {
			t.Fatalf("%s: payload boundary mismatch", tc.name)
		}
		msg, err := cotp.Decode(payload)
		if err != nil {
			t.Fatalf("Decode %s: %v", tc.name, err)
		}
		if msg.Type != tc.want {
			t.Errorf("%s: Type=%v, want %v", tc.name, msg.Type, tc.want)
		}
	}
	if _, err := r.ReadPacket(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after last packet, got %v", err)
	}
}

func TestTpktTruncationIsFramingErrorNotCOTP(t *testing.T) {
	encoded, err := (&cotp.CR{SourceRef: 1}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	pkt, err := tpkt.EncodePacket(encoded)
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}
	// Truncate after TPKT header so ReadPacket fails before COTP sees bytes.
	truncated := pkt[:tpkt.HeaderLength+1]
	r, err := tpkt.NewReader(bytes.NewReader(truncated), tpkt.ReaderConfig{})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	_, err = r.ReadPacket()
	if err == nil {
		t.Fatal("expected truncation error from tpkt")
	}
	if errors.Is(err, cotp.ErrTooShort) || errors.Is(err, cotp.ErrInvalidLI) {
		t.Fatalf("truncation should remain a TPKT framing error, got COTP error: %v", err)
	}
	// Ensure we never decode a truncated TPKT payload as COTP.
	if _, cerr := cotp.Decode(truncated); cerr == nil {
		t.Fatal("Decode of truncated TPKT buffer unexpectedly succeeded")
	}
}

func TestTpktNilConstructors(t *testing.T) {
	if _, err := tpkt.NewReader(nil, tpkt.ReaderConfig{}); !errors.Is(err, tpkt.ErrNilReader) {
		t.Fatalf("NewReader(nil): got %v, want ErrNilReader", err)
	}
	if _, err := tpkt.NewWriter(nil); !errors.Is(err, tpkt.ErrNilWriter) {
		t.Fatalf("NewWriter(nil): got %v, want ErrNilWriter", err)
	}
}

func TestTpktInvalidReaderConfig(t *testing.T) {
	_, err := tpkt.NewReader(bytes.NewReader(nil), tpkt.ReaderConfig{
		MaxPacketLength: 1, // below MinPacketLength
	})
	if !errors.Is(err, tpkt.ErrInvalidMaxPacketLength) {
		t.Fatalf("NewReader invalid MaxPacketLength: got %v, want ErrInvalidMaxPacketLength", err)
	}
}
