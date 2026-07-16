// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-tpkt"
)

func TestConn_LocalCloseUnblocksReadAndWrite(t *testing.T) {
	// Separate pipes so read and write can block independently.
	rLocal, rRemote := net.Pipe()
	wLocal, wRemote := net.Pipe()
	defer func() { _ = rRemote.Close() }()
	defer func() { _ = wRemote.Close() }()
	reader, err := tpkt.NewReader(rLocal, tpkt.ReaderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := tpkt.NewWriter(wLocal)
	if err != nil {
		t.Fatal(err)
	}
	refs := newReferenceAllocator()
	ref, err := refs.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	// Conn.Close closes only c.raw; use a stub that closes both directions.
	raw := &multiCloser{conns: []net.Conn{rLocal, wLocal}}
	conn := newOpenConn(raw, reader, writer, NegotiatedParameters{
		Class: Class0, MaxTPDULength: 1024, LocalRef: ref, RemoteRef: 2,
	}, DefaultMaxTSDULength, SizeProfileRFC1006Compat, ref, refs)

	readErr := make(chan error, 1)
	writeErr := make(chan error, 1)

	go func() {
		_, err := conn.reader.ReadPacket()
		readErr <- err
	}()
	go func() {
		// net.Pipe write blocks until the peer reads; nobody reads wRemote.
		payload := make([]byte, 64)
		writeErr <- conn.writer.WritePacket(payload)
	}()

	time.Sleep(50 * time.Millisecond)
	if err := conn.Close(); err != nil && !errors.Is(err, ErrClosed) {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("ReadPacket returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPacket not unblocked by Close")
	}
	select {
	case err := <-writeErr:
		if err == nil {
			t.Fatal("WritePacket returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WritePacket not unblocked by Close")
	}
}

type multiCloser struct {
	conns []net.Conn
}

func (m *multiCloser) Read(b []byte) (int, error)  { return m.conns[0].Read(b) }
func (m *multiCloser) Write(b []byte) (int, error) { return m.conns[1].Write(b) }
func (m *multiCloser) LocalAddr() net.Addr         { return m.conns[0].LocalAddr() }
func (m *multiCloser) RemoteAddr() net.Addr        { return m.conns[0].RemoteAddr() }
func (m *multiCloser) SetDeadline(t time.Time) error {
	_ = m.conns[0].SetDeadline(t)
	return m.conns[1].SetDeadline(t)
}
func (m *multiCloser) SetReadDeadline(t time.Time) error  { return m.conns[0].SetReadDeadline(t) }
func (m *multiCloser) SetWriteDeadline(t time.Time) error { return m.conns[1].SetWriteDeadline(t) }
func (m *multiCloser) Close() error {
	var err error
	for _, c := range m.conns {
		if e := c.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func TestConn_TerminalCauseCannotBeOverwritten(t *testing.T) {
	c1, c2 := net.Pipe()
	_ = c2.Close()

	reader, err := tpkt.NewReader(c1, tpkt.ReaderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := tpkt.NewWriter(c1)
	if err != nil {
		t.Fatal(err)
	}
	refs := newReferenceAllocator()
	ref, err := refs.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	conn := newOpenConn(c1, reader, writer, NegotiatedParameters{LocalRef: ref, RemoteRef: 1, MaxTPDULength: 128}, 1024, SizeProfileRFC1006Compat, ref, refs)

	first := &DisconnectError{Cause: io.EOF}
	if got := conn.abort(first); !errors.Is(got, ErrDisconnected) {
		t.Fatalf("abort: %v", got)
	}
	if err := conn.Close(); !errors.Is(err, ErrDisconnected) {
		t.Fatalf("Close after abort: %v, want first cause ErrDisconnected", err)
	}
	if errors.Is(err, ErrClosed) && !errors.Is(err, ErrDisconnected) {
		t.Fatalf("Close overwrote terminal cause with ErrClosed")
	}
	// Local close must not become the stored cause after peer disconnect.
	if conn.terminalKind() != terminalAborted {
		t.Fatalf("terminal kind = %v, want aborted", conn.terminalKind())
	}
}

func TestConn_LocalCloseReturnsErrClosedNotDisconnected(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	reader, err := tpkt.NewReader(c1, tpkt.ReaderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := tpkt.NewWriter(c1)
	if err != nil {
		t.Fatal(err)
	}
	refs := newReferenceAllocator()
	ref, err := refs.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	conn := newOpenConn(c1, reader, writer, NegotiatedParameters{LocalRef: ref, RemoteRef: 1, MaxTPDULength: 128}, 1024, SizeProfileRFC1006Compat, ref, refs)

	err = conn.Close()
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Close: %v, want ErrClosed", err)
	}
	if errors.Is(err, ErrDisconnected) {
		t.Fatal("local Close must not return ErrDisconnected")
	}
	if err2 := conn.Close(); !errors.Is(err2, ErrClosed) {
		t.Fatalf("second Close: %v", err2)
	}
}

func TestConn_ReferenceReleasedExactlyOnce(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	reader, err := tpkt.NewReader(c1, tpkt.ReaderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := tpkt.NewWriter(c1)
	if err != nil {
		t.Fatal(err)
	}
	refs := newReferenceAllocator()
	ref, err := refs.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if refs.Len() != 1 {
		t.Fatalf("active = %d, want 1", refs.Len())
	}
	conn := newOpenConn(c1, reader, writer, NegotiatedParameters{LocalRef: ref, RemoteRef: 1, MaxTPDULength: 128}, 1024, SizeProfileRFC1006Compat, ref, refs)

	_ = conn.Close()
	_ = conn.Close()
	conn.releaseRef() // extra explicit release must be idempotent
	if refs.Len() != 0 {
		t.Fatalf("active = %d, want 0 after single release", refs.Len())
	}
	if refs.Active(ref) {
		t.Fatalf("ref %d still active", ref)
	}
}

func TestConfig_PreflightClosesNothingOnItsOwn(t *testing.T) {
	// Preflight is pure validation; stream ownership is Connect/Accept's job.
	_, _, err := (ClientConfig{MaxTPDULength: 50}).preflight()
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	_, _, err = (ClientConfig{MaxTPDULength: 1024}).preflight()
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
}
