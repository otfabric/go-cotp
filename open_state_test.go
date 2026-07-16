// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestOpenState_UnexpectedTPDUs(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		wantTyp TPDUType
		drAlso  bool
	}{
		{"CR", mustMarshal(t, &CR{SourceRef: 1}), TypeCR, false},
		{"CC", mustMarshal(t, &CC{DestinationRef: 1, SourceRef: 2}), TypeCC, false},
		{"DR", mustMarshal(t, &DR{DestinationRef: 1, SourceRef: 2, Reason: 0}), TypeDR, true},
		{"DC", mustMarshal(t, &DC{DestinationRef: 1, SourceRef: 2}), TypeDC, false},
		{"ER", mustMarshal(t, &ER{DestinationRef: 1, RejectCause: 1}), TypeER, false},
		{"ED", mustMarshal(t, &ED{DestinationRef: uint16Ptr(1), TPDUNR: uint8Ptr(0), UserData: []byte{1}}), TypeED, false},
		{"AK", mustMarshal(t, &AK{DestinationRef: 1}), TypeAK, false},
		{"EA", mustMarshal(t, &EA{DestinationRef: 1}), TypeEA, false},
		{"RJ", mustMarshal(t, &RJ{DestinationRef: 1}), TypeRJ, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
			go func() { _ = writeRawTPKT(cli.raw, tc.payload) }()
			_, err := srv.ReadTSDU(context.Background())
			if !errors.Is(err, ErrUnexpectedTPDU) {
				t.Fatalf("err = %v, want ErrUnexpectedTPDU", err)
			}
			var u *UnexpectedTPDUError
			if !errors.As(err, &u) || u.Type != tc.wantTyp || u.Phase != PhaseDataTransfer {
				t.Fatalf("UnexpectedTPDUError = %#v", u)
			}
			if tc.drAlso && !errors.Is(err, ErrDisconnected) {
				t.Fatalf("open-state DR must also match ErrDisconnected, got %v", err)
			}
			if srv.terminalKind() != terminalAborted {
				t.Fatal("want aborted")
			}
			// Subsequent ops return the stored cause.
			if err2 := srv.WriteTSDU(context.Background(), []byte{1}); !errors.Is(err2, ErrUnexpectedTPDU) {
				t.Fatalf("WriteTSDU after abort: %v", err2)
			}
			_, err3 := srv.ReadTSDU(context.Background())
			if !errors.Is(err3, ErrUnexpectedTPDU) {
				t.Fatalf("ReadTSDU after abort: %v", err3)
			}
		})
	}
}

func TestOpenState_UnknownTPDUCode(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		// LI=2, reserved/unknown type 0x00.
		_ = writeRawTPKT(cli.raw, []byte{0x02, 0x00, 0x00})
	}()
	_, err := srv.ReadTSDU(context.Background())
	if err == nil || !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want wrapped codec/protocol error", err)
	}
	if srv.terminalKind() != terminalAborted {
		t.Fatal("want aborted")
	}
}

func TestOpenState_MalformedDTFixedPart(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		// Valid TPKT (≥3-octet payload); LI=1 is too short for a Class 0 DT fixed part.
		if err := writeRawTPKT(cli.raw, []byte{0x01, 0xF0, 0x80}); err != nil {
			t.Error(err)
		}
	}()
	_, err := srv.ReadTSDU(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if srv.terminalKind() != terminalAborted {
		t.Fatal("want aborted")
	}
}

func TestOpenState_DTF1(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() { _ = writeRawTPKT(cli.raw, []byte{0x02, 0xF1, 0x80, 0xAA}) }()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenState_DTNonZeroNR(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() { _ = writeRawTPKT(cli.raw, []byte{0x02, 0xF0, 0x81, 0xAA}) }()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenState_DTIllegalParameter(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		dt := &DT{
			EOT:        true,
			UserData:   []byte{1},
			Parameters: []Parameter{{Code: 0x99, Value: []byte{0xAA}}},
		}
		_ = writeRawTPKT(cli.raw, mustMarshal(t, dt))
	}()
	_, err := srv.ReadTSDU(context.Background())
	if err == nil || !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want protocol error", err)
	}
}

func TestOpenState_DTForbiddenParameterHelper(t *testing.T) {
	if err := validateOpenDTParameters([]Parameter{{Code: 0xC5, Value: []byte{1}}}); !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	if err := validateOpenDTParameters([]Parameter{{Code: 0x99, Value: nil}}); !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	if err := validateOpenDTParameters(nil); err != nil {
		t.Fatal(err)
	}
}

func TestOpenState_TPDUExceedsNegotiatedMax(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
	go func() {
		user := make([]byte, 126) // 3+126=129 > 128
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: true, UserData: user}))
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenState_UnexpectedAfterNonEOTIsIncomplete(t *testing.T) {
	types := []struct {
		name string
		p    []byte
	}{
		{"CR", mustMarshal(t, &CR{SourceRef: 9})},
		{"CC", mustMarshal(t, &CC{DestinationRef: 1, SourceRef: 2})},
		{"DR", mustMarshal(t, &DR{DestinationRef: 1, SourceRef: 2})},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
			go func() {
				_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: false, UserData: []byte{1}}))
				_ = writeRawTPKT(cli.raw, tc.p)
			}()
			_, err := srv.ReadTSDU(context.Background())
			if !errors.Is(err, ErrIncompleteTSDU) || !errors.Is(err, ErrUnexpectedTPDU) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestOpenState_MalformedSecondSegmentIncomplete(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
	go func() {
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &DT{EOT: false, UserData: []byte{1}}))
		_ = writeRawTPKT(cli.raw, []byte{0x02, 0xF1, 0x80, 0xAA})
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrIncompleteTSDU) || !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want Incomplete+protocol", err)
	}
}

func TestOpenState_TerminalCauseStableWithCloseRace(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	go func() {
		_ = writeRawTPKT(cli.raw, mustMarshal(t, &CR{SourceRef: 1}))
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrUnexpectedTPDU) {
		t.Fatalf("err = %v", err)
	}
	err2 := srv.Close()
	if !errors.Is(err2, ErrUnexpectedTPDU) {
		t.Fatalf("Close after protocol abort: %v, want first cause", err2)
	}
	if errors.Is(err2, ErrClosed) && !errors.Is(err2, ErrUnexpectedTPDU) {
		t.Fatal("Close must not overwrite terminal cause")
	}
}

func TestOpenState_BlockedWriterWakesOnReadAbort(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)

	writeErr := make(chan error, 1)
	go func() {
		// Large write that will block on the pipe until the peer aborts/closes.
		writeErr <- cli.WriteTSDU(context.Background(), make([]byte, 64*1024))
	}()
	time.Sleep(30 * time.Millisecond)

	go func() {
		_ = writeRawTPKT(srv.raw, mustMarshal(t, &DR{DestinationRef: 1, SourceRef: 2}))
	}()
	_, err := cli.ReadTSDU(context.Background())
	if !errors.Is(err, ErrUnexpectedTPDU) {
		t.Fatalf("ReadTSDU: %v", err)
	}

	select {
	case err := <-writeErr:
		if err == nil {
			t.Fatal("WriteTSDU should fail after peer abort")
		}
		// Writer sees the stored terminal cause or a stream error from close.
		if !errors.Is(err, ErrUnexpectedTPDU) && cli.terminalKind() == terminalNone {
			t.Fatalf("write err = %v; connection not terminal", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked writer not woken")
	}
}

func TestOpenState_PeerEOFPreserved(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	_ = cli.raw.Close()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, ErrDisconnected) || !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v", err)
	}
}

func TestDecodeOpenDT_HappyPath(t *testing.T) {
	p := mustMarshal(t, &DT{EOT: true, UserData: []byte{9, 8}})
	dt, err := decodeOpenDT(p, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !dt.EOT || len(dt.UserData) != 2 {
		t.Fatalf("%+v", dt)
	}
}

func uint16Ptr(v uint16) *uint16 { return &v }
