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

func writePeerCR(t *testing.T, c net.Conn, cr *CR) {
	t.Helper()
	writeTPDU(t, c, mustMarshal(t, cr))
}

func readPeerResponse(t *testing.T, c net.Conn) Decoded {
	t.Helper()
	tr, err := tpkt.NewReader(c, tpkt.ReaderConfig{})
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
	return d
}

func TestAccept_HappyPath(t *testing.T) {
	c1, c2 := net.Pipe()

	done := make(chan Decoded, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{
			SourceRef:       0x1111,
			ClassOption:     0,
			CalledSelector:  []byte{0x02},
			CallingSelector: []byte{0x01},
			TPDUSize:        uint8Ptr(0x0A),
			UserData:        []byte{0xAA},
		})
		done <- readPeerResponse(t, c1)
	}()

	conn, err := Accept(context.Background(), c2, ServerConfig{
		LocalSelector: []byte{0x02},
		MaxTPDULength: 1024,
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = conn.Close() }()
	resp := <-done
	if resp.Type != TypeCC || resp.CC == nil {
		t.Fatalf("peer got Type=%v, want CC", resp.Type)
	}
	if resp.CC.DestinationRef != 0x1111 {
		t.Fatalf("CC DST-REF = %#x, want 0x1111", resp.CC.DestinationRef)
	}
	if resp.CC.SourceRef == 0 {
		t.Fatal("CC SRC-REF is zero")
	}
	if resp.CC.TPDUSize == nil || *resp.CC.TPDUSize != 0x0A {
		t.Fatalf("CC TPDUSize = %v, want 0x0A", resp.CC.TPDUSize)
	}
	if resp.CC.PreferredMaxTPDUSize != nil {
		t.Fatalf("CC must not emit 0xF0 on standard path, got %v", resp.CC.PreferredMaxTPDUSize)
	}

	neg := conn.Negotiated()
	if neg.MaxTPDULength != 1024 {
		t.Fatalf("negotiated MaxTPDULength = %d, want 1024", neg.MaxTPDULength)
	}
	if neg.RemoteRef != 0x1111 || neg.LocalRef != resp.CC.SourceRef {
		t.Fatalf("refs local=%#x remote=%#x", neg.LocalRef, neg.RemoteRef)
	}
	if string(neg.PeerConnectData) != "\xaa" {
		t.Fatalf("PeerConnectData = %x", neg.PeerConnectData)
	}
}

func TestAccept_DefaultSelectorPolicyRejectsMismatch(t *testing.T) {
	c1, c2 := net.Pipe()

	done := make(chan Decoded, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{
			SourceRef:      0x10,
			CalledSelector: []byte{0xFF},
			TPDUSize:       uint8Ptr(0x0A),
		})
		done <- readPeerResponse(t, c1)
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{
		LocalSelector: []byte{0x02},
		MaxTPDULength: 1024,
	})
	var rej *RejectionError
	if !errors.As(err, &rej) || rej.Reason != ReasonAddressUnknown {
		t.Fatalf("err = %v, want RejectionError AddressUnknown", err)
	}
	resp := <-done
	if resp.Type != TypeDR || resp.DR == nil || DisconnectReason(resp.DR.Reason) != ReasonAddressUnknown {
		t.Fatalf("peer got %v, want DR AddressUnknown", resp)
	}
	if resp.DR.SourceRef != 0 {
		t.Fatalf("DR SRC-REF = %d, want 0 (unassigned)", resp.DR.SourceRef)
	}
}

func TestAccept_DefaultSelectorPolicyNilAllowsAbsent(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{SourceRef: 1, TPDUSize: uint8Ptr(0x0A)})
		_ = readPeerResponse(t, c1)
	}()

	conn, err := Accept(context.Background(), c2, ServerConfig{MaxTPDULength: 1024})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	_ = conn.Close()
}

func TestAccept_OnConnectAccept(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{SourceRef: 2, TPDUSize: uint8Ptr(0x0A), UserData: []byte{1}})
		_ = readPeerResponse(t, c1)
	}()

	var saw ConnectIndication
	conn, err := Accept(context.Background(), c2, ServerConfig{
		MaxTPDULength: 1024,
		OnConnect: func(_ context.Context, ind ConnectIndication) (AcceptDecision, error) {
			saw = ind
			ind.ConnectData[0] = 0xFF // must not affect engine copy retained elsewhere
			return AcceptDecision{Action: ConnectAccept, ConnectData: []byte{0xBB}, MaxTPDULength: 512}, nil
		},
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if saw.SourceRef != 2 || saw.MaxTPDULength != 1024 {
		t.Fatalf("indication = %+v", saw)
	}
	if conn.Negotiated().MaxTPDULength != 512 {
		t.Fatalf("negotiated = %d, want 512", conn.Negotiated().MaxTPDULength)
	}
}

func TestAccept_OnConnectRejectSendsDR(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan Decoded, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{SourceRef: 3, TPDUSize: uint8Ptr(0x0A)})
		done <- readPeerResponse(t, c1)
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{
		MaxTPDULength: 1024,
		OnConnect: func(context.Context, ConnectIndication) (AcceptDecision, error) {
			return AcceptDecision{Action: ConnectReject, RejectReason: ReasonCongestionAtTSAP}, nil
		},
	})
	var rej *RejectionError
	if !errors.As(err, &rej) || rej.Reason != ReasonCongestionAtTSAP {
		t.Fatalf("err = %v", err)
	}
	resp := <-done
	if resp.Type != TypeDR || DisconnectReason(resp.DR.Reason) != ReasonCongestionAtTSAP {
		t.Fatalf("peer got %v", resp)
	}
}

func TestAccept_OnConnectErrorClosesWithoutDR(t *testing.T) {
	c1, c2 := net.Pipe()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{SourceRef: 4, TPDUSize: uint8Ptr(0x0A)})
		tr, err := tpkt.NewReader(c1, tpkt.ReaderConfig{})
		if err != nil {
			t.Error(err)
			return
		}
		_, err = tr.ReadPacket()
		if err == nil {
			t.Error("expected no DR/CC; peer should see close/EOF")
		}
	}()

	cbErr := errors.New("policy boom")
	_, err := Accept(context.Background(), c2, ServerConfig{
		MaxTPDULength: 1024,
		OnConnect: func(context.Context, ConnectIndication) (AcceptDecision, error) {
			return AcceptDecision{}, cbErr
		},
	})
	if !errors.Is(err, ErrHandshake) || !errors.Is(err, cbErr) {
		t.Fatalf("err = %v, want ErrHandshake + callback error", err)
	}
	select {
	case <-peerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("peer not unblocked")
	}
}

func TestAccept_OnConnectInvalidAction(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{SourceRef: 5, TPDUSize: uint8Ptr(0x0A)})
		buf := make([]byte, 1)
		_, _ = c1.Read(buf)
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{
		MaxTPDULength: 1024,
		OnConnect: func(context.Context, ConnectIndication) (AcceptDecision, error) {
			return AcceptDecision{Action: ConnectAction(99)}, nil
		},
	})
	if !errors.Is(err, ErrHandshake) || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestAccept_ConnectDataTooLargeBeforeCC(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{SourceRef: 6, TPDUSize: uint8Ptr(0x0A)})
		buf := make([]byte, 1)
		_, _ = c1.Read(buf)
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{
		MaxTPDULength: 1024,
		OnConnect: func(context.Context, ConnectIndication) (AcceptDecision, error) {
			return AcceptDecision{Action: ConnectAccept, ConnectData: make([]byte, MaxConnectDataLength+1)}, nil
		},
	})
	if !errors.Is(err, ErrHandshake) || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestAccept_InvalidClass0CRSendsER(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan Decoded, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{
			CDT:         1,
			SourceRef:   0x20,
			ClassOption: 0,
			TPDUSize:    uint8Ptr(0x0A),
		})
		done <- readPeerResponse(t, c1)
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	resp := <-done
	if resp.Type != TypeER || resp.ER == nil {
		t.Fatalf("peer got %v, want ER", resp)
	}
	if resp.ER.DestinationRef != 0x20 || resp.ER.RejectCause != erCauseInvalidParameterValue {
		t.Fatalf("ER = %+v", resp.ER)
	}
}

func TestAccept_ForbiddenParameterSendsER(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan Decoded, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{
			SourceRef:  0x21,
			Parameters: []Parameter{{Code: 0xC5, Value: []byte{0x01}}},
			TPDUSize:   uint8Ptr(0x0A),
		})
		done <- readPeerResponse(t, c1)
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	resp := <-done
	if resp.Type != TypeER || resp.ER.RejectCause != erCauseInvalidParameterCode {
		t.Fatalf("peer got %v", resp)
	}
}

func TestAccept_NonClass0PreferredSendsDR(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan Decoded, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{
			SourceRef:   0x22,
			ClassOption: 0x20, // class 2
			TPDUSize:    uint8Ptr(0x0A),
		})
		done <- readPeerResponse(t, c1)
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{MaxTPDULength: 1024})
	var rej *RejectionError
	if !errors.As(err, &rej) || rej.Reason != ReasonNegotiationFailed {
		t.Fatalf("err = %v", err)
	}
	resp := <-done
	if resp.Type != TypeDR || DisconnectReason(resp.DR.Reason) != ReasonNegotiationFailed {
		t.Fatalf("peer got %v", resp)
	}
}

func TestAccept_MalformedClosesWithoutResponse(t *testing.T) {
	c1, c2 := net.Pipe()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		defer func() { _ = c1.Close() }()
		// Valid TPKT, garbage COTP.
		writeTPDU(t, c1, []byte{0x02, 0x00, 0x00})
		tr, _ := tpkt.NewReader(c1, tpkt.ReaderConfig{})
		_, err := tr.ReadPacket()
		if err == nil {
			t.Error("expected close without protocol response")
		}
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-peerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("peer not unblocked")
	}
}

func TestAccept_UnexpectedTPDUClosesWithoutResponse(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer func() { _ = c1.Close() }()
		writeTPDU(t, c1, mustMarshal(t, &DT{EOT: true, UserData: []byte{1}}))
		buf := make([]byte, 1)
		_, _ = c1.Read(buf)
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrUnexpectedTPDU) {
		t.Fatalf("err = %v", err)
	}
}

func TestAccept_ZeroSourceRefClosesWithoutER(t *testing.T) {
	c1, c2 := net.Pipe()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{SourceRef: 0, TPDUSize: uint8Ptr(0x0A)})
		tr, _ := tpkt.NewReader(c1, tpkt.ReaderConfig{})
		_, err := tr.ReadPacket()
		if err == nil {
			t.Error("expected no ER for unassociable zero SRC-REF")
		}
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{MaxTPDULength: 1024})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-peerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("peer not unblocked")
	}
}

func TestAccept_SelectedSizeMatchesCCPath(t *testing.T) {
	c1, c2 := net.Pipe()
	done := make(chan Decoded, 1)
	go func() {
		defer func() { _ = c1.Close() }()
		// Preferred offer 1024 (8 units); server ceiling 1000 → preferred path 896.
		u := uint32(8)
		writePeerCR(t, c1, &CR{
			SourceRef:            0x33,
			PreferredMaxTPDUSize: &u,
			TPDUSize:             uint8Ptr(0x0A), // dual offer
		})
		done <- readPeerResponse(t, c1)
	}()

	conn, err := Accept(context.Background(), c2, ServerConfig{
		MaxTPDULength: 1000,
		SizeProfile:   SizeProfilePreferredMaximum,
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = conn.Close() }()
	resp := <-done
	if resp.CC.PreferredMaxTPDUSize == nil || *resp.CC.PreferredMaxTPDUSize != 7 {
		t.Fatalf("CC preferred units = %v, want 7 (896)", resp.CC.PreferredMaxTPDUSize)
	}
	if resp.CC.TPDUSize != nil {
		t.Fatalf("CC must not send both 0xC0 and 0xF0, got TPDUSize=%v", resp.CC.TPDUSize)
	}
	if conn.Negotiated().MaxTPDULength != 896 {
		t.Fatalf("negotiated = %d, want 896 (must match wire)", conn.Negotiated().MaxTPDULength)
	}
}

func TestAccept_FailureReleasesReference(t *testing.T) {
	before := defaultRefs.Len()
	c1, c2 := net.Pipe()
	go func() {
		defer func() { _ = c1.Close() }()
		writePeerCR(t, c1, &CR{SourceRef: 7, TPDUSize: uint8Ptr(0x0A)})
		_ = readPeerResponse(t, c1) // DR
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{
		LocalSelector: []byte{0x01},
		MaxTPDULength: 1024,
	})
	if !errors.Is(err, ErrConnectionRefused) {
		t.Fatalf("err = %v", err)
	}
	if defaultRefs.Len() != before {
		t.Fatalf("active refs = %d, want %d (no leak on reject)", defaultRefs.Len(), before)
	}
}

func TestAccept_ConfigFailureClosesStream(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	closed := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		_, _ = c1.Read(buf)
		close(closed)
	}()

	_, err := Accept(context.Background(), c2, ServerConfig{MaxTPDULength: 50})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("stream not closed on config failure")
	}
}

func TestAccept_NilConn(t *testing.T) {
	_, err := Accept(context.Background(), nil, ServerConfig{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
}
