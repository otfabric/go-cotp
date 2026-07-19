// SPDX-License-Identifier: MIT

package cotp_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-cotp"
	"github.com/otfabric/go-tpkt"
)

func writePeerTPDU(t *testing.T, c net.Conn, tpdu []byte) {
	t.Helper()
	w, err := tpkt.NewWriter(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(tpdu); err != nil {
		t.Fatal(err)
	}
}

func readPeerTPDU(t *testing.T, c net.Conn) []byte {
	t.Helper()
	r, err := tpkt.NewReader(c, tpkt.ReaderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustMarshalTPDU(t *testing.T, v interface{ MarshalBinary() ([]byte, error) }) []byte {
	t.Helper()
	b, err := v.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustDecodeCR(t *testing.T, b []byte) *cotp.CR {
	t.Helper()
	msg, err := cotp.Decode(b)
	if err != nil || msg.CR == nil {
		t.Fatalf("decode CR: %v type=%v", err, msg.Type)
	}
	return msg.CR
}

func u8(v uint8) *uint8 { return &v }

func u16(v uint16) *uint16 { return &v }

// acceptWithRawClient completes a Class 0 handshake with a real Accept endpoint
// and a raw TPKT peer acting as client. Returns the open server Conn and the
// raw peer connection for adversarial injection.
func acceptWithRawClient(t *testing.T, srvCfg cotp.ServerConfig, cr *cotp.CR) (srv *cotp.Conn, peer net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	errCh := make(chan error, 1)
	var conn *cotp.Conn
	go func() {
		var err error
		conn, err = cotp.Accept(context.Background(), c2, srvCfg)
		errCh <- err
	}()
	if cr.TPDUSize == nil {
		cr.TPDUSize = u8(0x0A) // 1024
	}
	if cr.SourceRef == 0 {
		cr.SourceRef = 0x1111
	}
	writePeerTPDU(t, c1, mustMarshalTPDU(t, cr))
	cc := readPeerTPDU(t, c1)
	msg, err := cotp.Decode(cc)
	if err != nil || msg.Type != cotp.TypeCC {
		t.Fatalf("want CC, got type=%v err=%v", msg.Type, err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = c1.Close()
	})
	return conn, c1
}

func TestAdversarial_HandshakeMalformedCR(t *testing.T) {
	c1, c2 := net.Pipe()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		defer func() { _ = c1.Close() }()
		writePeerTPDU(t, c1, []byte{0x02, 0x00, 0x00})
		r, _ := tpkt.NewReader(c1, tpkt.ReaderConfig{})
		_, err := r.ReadPacket()
		if err == nil {
			t.Error("expected close without protocol response")
		}
	}()
	_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-peerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("peer not unblocked")
	}
}

func TestAdversarial_HandshakeZeroSourceRef(t *testing.T) {
	c1, c2 := net.Pipe()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		defer func() { _ = c1.Close() }()
		writePeerTPDU(t, c1, mustMarshalTPDU(t, &cotp.CR{SourceRef: 0, TPDUSize: u8(0x0A)}))
		r, _ := tpkt.NewReader(c1, tpkt.ReaderConfig{})
		_, err := r.ReadPacket()
		if err == nil {
			t.Error("expected close without ER (unassociable)")
		}
	}()
	_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-peerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("peer not unblocked")
	}
}

func TestAdversarial_HandshakeNonZeroDSTRef(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerTPDU(t, c1, mustMarshalTPDU(t, &cotp.CR{DestinationRef: 1, SourceRef: 2, TPDUSize: u8(0x0A)}))
		done <- readPeerTPDU(t, c1)
	}()
	_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	msg, err := cotp.Decode(<-done)
	if err != nil || msg.Type != cotp.TypeER {
		t.Fatalf("want ER, got %v err=%v", msg.Type, err)
	}
}

func TestAdversarial_HandshakeUnsupportedClass(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerTPDU(t, c1, mustMarshalTPDU(t, &cotp.CR{SourceRef: 3, ClassOption: 0x20, TPDUSize: u8(0x0A)}))
		done <- readPeerTPDU(t, c1)
	}()
	_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrConnectionRefused) {
		t.Fatalf("err = %v", err)
	}
	var rej *cotp.RejectionError
	if !errors.As(err, &rej) || rej.Reason != cotp.ReasonNegotiationFailed {
		t.Fatalf("RejectionError = %#v", rej)
	}
	msg, err := cotp.Decode(<-done)
	if err != nil || msg.Type != cotp.TypeDR {
		t.Fatalf("want DR, got %v", msg.Type)
	}
	if cotp.DisconnectReason(msg.DR.Reason) != cotp.ReasonNegotiationFailed {
		t.Fatalf("reason = %d", msg.DR.Reason)
	}
}

func TestAdversarial_HandshakeIllegalCDT(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerTPDU(t, c1, mustMarshalTPDU(t, &cotp.CR{CDT: 1, SourceRef: 4, TPDUSize: u8(0x0A)}))
		done <- readPeerTPDU(t, c1)
	}()
	_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	msg, err := cotp.Decode(<-done)
	if err != nil || msg.Type != cotp.TypeER {
		t.Fatalf("want ER, got %v", msg.Type)
	}
}

func TestAdversarial_HandshakeBadSelector(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerTPDU(t, c1, mustMarshalTPDU(t, &cotp.CR{
			SourceRef:      5,
			CalledSelector: []byte{0xFF},
			TPDUSize:       u8(0x0A),
		}))
		done <- readPeerTPDU(t, c1)
	}()
	_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{
		LocalSelector: []byte{0x01},
		MaxTPDULength: 1024,
	})
	if !errors.Is(err, cotp.ErrConnectionRefused) {
		t.Fatalf("err = %v", err)
	}
	msg, err := cotp.Decode(<-done)
	if err != nil || msg.Type != cotp.TypeDR {
		t.Fatalf("want DR, got %v", msg.Type)
	}
	if cotp.DisconnectReason(msg.DR.Reason) != cotp.ReasonAddressUnknown {
		t.Fatalf("reason = %d", msg.DR.Reason)
	}
}

func TestAdversarial_HandshakeForbiddenParameter(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerTPDU(t, c1, mustMarshalTPDU(t, &cotp.CR{
			SourceRef:  6,
			TPDUSize:   u8(0x0A),
			Parameters: []cotp.Parameter{{Code: 0xC5, Value: []byte{1}}},
		}))
		done <- readPeerTPDU(t, c1)
	}()
	_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	msg, err := cotp.Decode(<-done)
	if err != nil || msg.Type != cotp.TypeER {
		t.Fatalf("want ER, got %v", msg.Type)
	}
}

func TestAdversarial_HandshakeInvalidSizeCode(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		// 0x11 = undefined TPDU size code; not in X.224 §13.3.4 b.
		writePeerTPDU(t, c1, mustMarshalTPDU(t, &cotp.CR{SourceRef: 7, TPDUSize: u8(0x11)}))
		done <- readPeerTPDU(t, c1)
	}()
	_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	msg, err := cotp.Decode(<-done)
	if err != nil || msg.Type != cotp.TypeER {
		t.Fatalf("want ER, got %v", msg.Type)
	}
}

func TestAdversarial_HandshakeOversizedCR(t *testing.T) {
	c1, c2 := net.Pipe()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		defer func() { _ = c1.Close() }()
		// Valid TPKT framing with COTP payload larger than MaxCRTPDULength.
		oversized := make([]byte, cotp.MaxCRTPDULength+1)
		oversized[0] = 0x06
		oversized[1] = 0xE0
		writePeerTPDU(t, c1, oversized)
		r, _ := tpkt.NewReader(c1, tpkt.ReaderConfig{})
		_, _ = r.ReadPacket()
	}()
	_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-peerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("peer not unblocked")
	}
}

func TestAdversarial_HandshakeCallbackReject(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerTPDU(t, c1, mustMarshalTPDU(t, &cotp.CR{SourceRef: 8, TPDUSize: u8(0x0A)}))
		done <- readPeerTPDU(t, c1)
	}()
	_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{
		MaxTPDULength: 1024,
		OnConnect: func(context.Context, cotp.ConnectIndication) (cotp.AcceptDecision, error) {
			return cotp.AcceptDecision{Action: cotp.ConnectReject, RejectReason: cotp.ReasonCongestionAtTSAP}, nil
		},
	})
	if !errors.Is(err, cotp.ErrConnectionRefused) {
		t.Fatalf("err = %v", err)
	}
	msg, err := cotp.Decode(<-done)
	if err != nil || msg.Type != cotp.TypeDR {
		t.Fatalf("want DR, got %v", msg.Type)
	}
	if cotp.DisconnectReason(msg.DR.Reason) != cotp.ReasonCongestionAtTSAP {
		t.Fatalf("reason = %d", msg.DR.Reason)
	}
}

func TestAdversarial_HandshakePeerClosesBeforeCC(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		_ = readPeerTPDU(t, c2) // consume CR
		_ = c2.Close()
	}()
	_, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrDisconnected) || !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v", err)
	}
}

func TestAdversarial_HandshakeMalformedCC(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		_ = readPeerTPDU(t, c2)
		writePeerTPDU(t, c2, []byte{0x02, 0x00, 0x00})
	}()
	_, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
}

func TestAdversarial_HandshakeWrongCCRefs(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		cr := mustDecodeCR(t, readPeerTPDU(t, c2))
		writePeerTPDU(t, c2, mustMarshalTPDU(t, &cotp.CC{
			DestinationRef: cr.SourceRef + 1,
			SourceRef:      0x2222,
			TPDUSize:       u8(0x0A),
		}))
	}()
	_, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
}

func TestAdversarial_HandshakeWrongSizeSelection(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		cr := mustDecodeCR(t, readPeerTPDU(t, c2))
		writePeerTPDU(t, c2, mustMarshalTPDU(t, &cotp.CC{
			DestinationRef: cr.SourceRef,
			SourceRef:      0x2222,
			TPDUSize:       u8(0x0B), // 2048 > client 1024 offer
		}))
	}()
	_, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
}

func TestAdversarial_HandshakeOmittedCCUnderPreferredMaximum(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		cr := mustDecodeCR(t, readPeerTPDU(t, c2))
		writePeerTPDU(t, c2, mustMarshalTPDU(t, &cotp.CC{
			DestinationRef: cr.SourceRef,
			SourceRef:      0x2222,
			// omit size parameters
		}))
	}()
	_, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{
		MaxTPDULength: 1024,
		SizeProfile:   cotp.SizeProfilePreferredMaximum,
	})
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
}

func TestAdversarial_OpenStateIllegalTPDUs(t *testing.T) {
	nr := uint8(0)
	cases := []struct {
		name string
		p    []byte
		want error
	}{
		{"CR", mustMarshalTPDU(t, &cotp.CR{SourceRef: 1}), cotp.ErrUnexpectedTPDU},
		{"CC", mustMarshalTPDU(t, &cotp.CC{DestinationRef: 1, SourceRef: 2}), cotp.ErrUnexpectedTPDU},
		{"DR", mustMarshalTPDU(t, &cotp.DR{DestinationRef: 1, SourceRef: 2}), cotp.ErrUnexpectedTPDU},
		{"ER", mustMarshalTPDU(t, &cotp.ER{DestinationRef: 1}), cotp.ErrUnexpectedTPDU},
		{"DC", mustMarshalTPDU(t, &cotp.DC{DestinationRef: 1, SourceRef: 2}), cotp.ErrUnexpectedTPDU},
		{"AK", mustMarshalTPDU(t, &cotp.AK{DestinationRef: 1}), cotp.ErrUnexpectedTPDU},
		{"EA", mustMarshalTPDU(t, &cotp.EA{DestinationRef: 1}), cotp.ErrUnexpectedTPDU},
		{"RJ", mustMarshalTPDU(t, &cotp.RJ{DestinationRef: 1}), cotp.ErrUnexpectedTPDU},
		{"ED", mustMarshalTPDU(t, &cotp.ED{DestinationRef: u16(1), TPDUNR: &nr, UserData: []byte{1}}), cotp.ErrUnexpectedTPDU},
		{"F1", []byte{0x02, 0xF1, 0x80, 0x01}, cotp.ErrHandshake},
		{"nonzero-NR", []byte{0x02, 0xF0, 0x81, 0x01}, cotp.ErrHandshake},
		{"empty-seg", []byte{0x02, 0xF0, 0x80}, cotp.ErrHandshake},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, peer := acceptWithRawClient(t, cotp.ServerConfig{MaxTPDULength: 1024}, &cotp.CR{})
			go func() { writePeerTPDU(t, peer, tc.p) }()
			_, err := srv.ReadTSDU(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.name == "DR" && !errors.Is(err, cotp.ErrDisconnected) {
				t.Fatalf("open DR must also match ErrDisconnected, got %v", err)
			}
			err2 := srv.WriteTSDU(context.Background(), []byte{1})
			if err2 == nil {
				t.Fatal("write succeeded after open-state failure")
			}
			if !errors.Is(err2, tc.want) && !errors.Is(err2, err) {
				t.Fatalf("write after abort: %v (read was %v)", err2, err)
			}
		})
	}
}

func TestAdversarial_EOFMidTSDU(t *testing.T) {
	srv, peer := acceptWithRawClient(t, cotp.ServerConfig{MaxTPDULength: 128}, &cotp.CR{TPDUSize: u8(0x07)})
	go func() {
		writePeerTPDU(t, peer, mustMarshalTPDU(t, &cotp.DT{EOT: false, UserData: []byte{1}}))
		_ = peer.Close()
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, cotp.ErrIncompleteTSDU) || !errors.Is(err, cotp.ErrDisconnected) {
		t.Fatalf("err = %v", err)
	}
}

func TestAdversarial_OversizedTPDU(t *testing.T) {
	srv, peer := acceptWithRawClient(t, cotp.ServerConfig{MaxTPDULength: 128}, &cotp.CR{TPDUSize: u8(0x07)})
	go func() {
		writePeerTPDU(t, peer, mustMarshalTPDU(t, &cotp.DT{
			EOT:      true,
			UserData: bytes.Repeat([]byte{9}, 126), // 3+126 = 129 > 128
		}))
	}()
	_, err := srv.ReadTSDU(context.Background())
	if !errors.Is(err, cotp.ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
}

func TestAdversarial_EndlessNonEOTHitsBound(t *testing.T) {
	srv, peer := acceptWithRawClient(t,
		cotp.ServerConfig{MaxTPDULength: 128, MaxTSDULength: 250},
		&cotp.CR{TPDUSize: u8(0x07)},
	)
	errCh := make(chan error, 1)
	go func() {
		_, err := srv.ReadTSDU(context.Background())
		errCh <- err
	}()
	writePeerTPDU(t, peer, mustMarshalTPDU(t, &cotp.DT{EOT: false, UserData: bytes.Repeat([]byte{1}, 125)}))
	writePeerTPDU(t, peer, mustMarshalTPDU(t, &cotp.DT{EOT: false, UserData: bytes.Repeat([]byte{2}, 125)}))
	writePeerTPDU(t, peer, mustMarshalTPDU(t, &cotp.DT{EOT: false, UserData: []byte{3}}))
	select {
	case err := <-errCh:
		if !errors.Is(err, cotp.ErrTSDUTooLarge) {
			t.Fatalf("err = %v, want ErrTSDUTooLarge", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestAdversarial_PeerResetDuringWrite(t *testing.T) {
	srv, peer := acceptWithRawClient(t, cotp.ServerConfig{MaxTPDULength: 128}, &cotp.CR{TPDUSize: u8(0x07)})
	errCh := make(chan error, 1)
	go func() {
		// Large enough to block on net.Pipe until the peer closes.
		errCh <- srv.WriteTSDU(context.Background(), bytes.Repeat([]byte{0xAB}, 64*1024))
	}()
	time.Sleep(30 * time.Millisecond)
	_ = peer.Close()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("WriteTSDU should fail after peer reset")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked writer not woken")
	}
}
