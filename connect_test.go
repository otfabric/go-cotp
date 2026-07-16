// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-tpkt"
)

func writeTPDU(t *testing.T, w net.Conn, tpdu []byte) {
	t.Helper()
	tw, err := tpkt.NewWriter(w)
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.WritePacket(tpdu); err != nil {
		t.Fatal(err)
	}
}

func readPeerCR(t *testing.T, r net.Conn) *CR {
	t.Helper()
	tr, err := tpkt.NewReader(r, tpkt.ReaderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := tr.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(payload)
	if err != nil {
		t.Fatal(err)
	}
	if d.Type != TypeCR || d.CR == nil {
		t.Fatalf("peer got Type=%v, want CR", d.Type)
	}
	return d.CR
}

// peerRespond runs fn against the accepting pipe end and closes it afterward.
// Failures are reported on the test via t.Error (safe from a child goroutine).
func peerRespond(t *testing.T, c2 net.Conn, fn func(net.Conn) error) {
	t.Helper()
	go func() {
		defer func() { _ = c2.Close() }()
		if err := fn(c2); err != nil {
			t.Errorf("peer: %v", err)
		}
	}()
}

func peerReadCR(c net.Conn) (*CR, error) {
	tr, err := tpkt.NewReader(c, tpkt.ReaderConfig{})
	if err != nil {
		return nil, err
	}
	payload, err := tr.ReadPacket()
	if err != nil {
		return nil, err
	}
	d, err := Decode(payload)
	if err != nil {
		return nil, err
	}
	if d.Type != TypeCR || d.CR == nil {
		return nil, errors.New("expected CR")
	}
	return d.CR, nil
}

func peerWriteTPDU(c net.Conn, tpdu []byte) error {
	tw, err := tpkt.NewWriter(c)
	if err != nil {
		return err
	}
	return tw.WritePacket(tpdu)
}

func mustMarshal(t *testing.T, m interface{ MarshalBinary() ([]byte, error) }) []byte {
	t.Helper()
	b, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestConnect_HappyPath(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	done := make(chan error, 1)
	go func() {
		cr := readPeerCR(t, c2)
		if cr.SourceRef == 0 || cr.DestinationRef != 0 || cr.CDT != 0 || cr.ClassOption != 0 {
			done <- errors.New("bad CR fixed fields")
			return
		}
		cc := &CC{
			CDT:            0,
			DestinationRef: cr.SourceRef,
			SourceRef:      0x2222,
			ClassOption:    0,
			TPDUSize:       uint8Ptr(0x0A), // 1024
			CalledSelector: []byte{0x02},
			UserData:       []byte{0xAA},
		}
		writeTPDU(t, c2, mustMarshal(t, cc))
		done <- nil
	}()

	conn, err := Connect(context.Background(), c1, ClientConfig{
		LocalSelector:  []byte{0x01},
		RemoteSelector: []byte{0x02},
		MaxTPDULength:  1024,
		ConnectData:    []byte{0xBB},
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	neg := conn.Negotiated()
	if neg.MaxTPDULength != 1024 {
		t.Fatalf("MaxTPDULength = %d, want 1024", neg.MaxTPDULength)
	}
	if neg.RemoteRef != 0x2222 {
		t.Fatalf("RemoteRef = %#x", neg.RemoteRef)
	}
	if neg.LocalRef == 0 {
		t.Fatal("LocalRef is zero")
	}
	if string(neg.PeerConnectData) != "\xaa" {
		t.Fatalf("PeerConnectData = %x", neg.PeerConnectData)
	}
}

func TestConnect_DRRefusalTypedReason(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		cr := readPeerCR(t, c2)
		dr := &DR{
			DestinationRef: cr.SourceRef,
			SourceRef:      0x10,
			Reason:         uint8(ReasonAddressUnknown),
			UserData:       []byte("nope"),
		}
		writeTPDU(t, c2, mustMarshal(t, dr))
	}()

	_, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrConnectionRefused) {
		t.Fatalf("err = %v, want ErrConnectionRefused", err)
	}
	var rej *RejectionError
	if !errors.As(err, &rej) {
		t.Fatalf("err = %v, want RejectionError", err)
	}
	if rej.Reason != ReasonAddressUnknown {
		t.Fatalf("Reason = %d, want %d", rej.Reason, ReasonAddressUnknown)
	}
}

func TestConnect_ERDuringHandshake(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		cr := readPeerCR(t, c2)
		er := &ER{DestinationRef: cr.SourceRef, RejectCause: 1}
		writeTPDU(t, c2, mustMarshal(t, er))
	}()

	_, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestConnect_UnexpectedTPDU(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		_ = readPeerCR(t, c2)
		dt := &DT{EOT: true, UserData: []byte{0x01}}
		writeTPDU(t, c2, mustMarshal(t, dt))
	}()

	_, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrUnexpectedTPDU) {
		t.Fatalf("err = %v, want ErrUnexpectedTPDU", err)
	}
	var u *UnexpectedTPDUError
	if !errors.As(err, &u) || u.Type != TypeDT || u.Phase != PhaseHandshake {
		t.Fatalf("UnexpectedTPDUError = %#v", u)
	}
}

func TestConnect_BadDestinationReference(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		_ = readPeerCR(t, c2)
		cc := &CC{DestinationRef: 0x9999, SourceRef: 0x2222, ClassOption: 0}
		writeTPDU(t, c2, mustMarshal(t, cc))
	}()

	_, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestConnect_BadSourceReferenceZero(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		cr := readPeerCR(t, c2)
		cc := &CC{DestinationRef: cr.SourceRef, SourceRef: 0, ClassOption: 0}
		writeTPDU(t, c2, mustMarshal(t, cc))
	}()

	_, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestConnect_InvalidClass0Fields(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		cr := readPeerCR(t, c2)
		cc := &CC{CDT: 1, DestinationRef: cr.SourceRef, SourceRef: 2, ClassOption: 0}
		writeTPDU(t, c2, mustMarshal(t, cc))
	}()

	_, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestConnect_WrongSizeSelection(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		cr := readPeerCR(t, c2)
		// Peer selects 2048 while client offered only 1024 standard.
		cc := &CC{
			DestinationRef: cr.SourceRef,
			SourceRef:      2,
			ClassOption:    0,
			TPDUSize:       uint8Ptr(0x0B),
		}
		writeTPDU(t, c2, mustMarshal(t, cc))
	}()

	_, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestConnect_MismatchedReturnedSelector(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		cr := readPeerCR(t, c2)
		cc := &CC{
			DestinationRef: cr.SourceRef,
			SourceRef:      2,
			ClassOption:    0,
			CalledSelector: []byte{0xFF},
			TPDUSize:       uint8Ptr(0x0A),
		}
		writeTPDU(t, c2, mustMarshal(t, cc))
	}()

	_, err := Connect(context.Background(), c1, ClientConfig{
		RemoteSelector: []byte{0x02},
		MaxTPDULength:  1024,
	})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestConnect_MalformedCOTP(t *testing.T) {
	c1, c2 := net.Pipe()

	peerRespond(t, c2, func(c net.Conn) error {
		if _, err := peerReadCR(c); err != nil {
			return err
		}
		// Valid TPKT (≥3-octet payload), invalid COTP type/LI.
		return peerWriteTPDU(c, []byte{0x02, 0x00, 0x00})
	})

	_, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v, want ErrHandshake", err)
	}
}

func TestConnect_MalformedTPKT(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		_ = readPeerCR(t, c2)
		// Truncated TPKT header.
		_, _ = c2.Write([]byte{0x03, 0x00, 0x00})
		_ = c2.Close()
	}()

	_, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: 1024})
	if err == nil {
		t.Fatal("expected framing error")
	}
	// Framing may surface as a raw stream error or wrapped form; either is fine
	// so long as Connect does not succeed.
	_ = err
}

func TestConnect_ContextCancelAfterIOStartsClosesStream(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	ctx, cancel := context.WithCancel(context.Background())

	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		// Read the CR (I/O started), then wait; client cancels while awaiting CC.
		_ = readPeerCR(t, c2)
		buf := make([]byte, 1)
		_, _ = c2.Read(buf) // unblocked when client closes
	}()

	errCh := make(chan error, 1)
	go func() {
		_, err := Connect(ctx, c1, ClientConfig{MaxTPDULength: 1024})
		errCh <- err
	}()

	// Ensure CR has been written so I/O has started.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect did not return after cancel")
	}

	select {
	case <-peerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("peer was not unblocked; stream not closed after cancel")
	}
}

func TestConnect_NilConn(t *testing.T) {
	_, err := Connect(context.Background(), nil, ClientConfig{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestConnect_ConfigFailureClosesStream(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	closed := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		_, _ = c2.Read(buf)
		close(closed)
	}()

	_, err := Connect(context.Background(), c1, ClientConfig{MaxTPDULength: 50})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("peer side was not unblocked; stream not closed on config failure")
	}
}

func TestConnect_ContextCanceledBeforeIO(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Connect(ctx, c1, ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrClosed) {
		t.Fatal("pre-I/O cancel must not wrap ErrClosed")
	}
}

func uint8Ptr(v uint8) *uint8 { return &v }
