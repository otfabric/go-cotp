// SPDX-License-Identifier: MIT

package cotp

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-tpkt"
)

// scriptConn is a net.Conn whose peer is the test's script, for tests that
// must know where the code under test is without sleeping.
//
// Read returns the octets of src. Once src is drained it returns readErr, or,
// when readErr is nil, reports on idle that the reader has consumed
// everything and waits for Close. Write accepts every octet, or returns
// writeErr. Deadlines are accepted and ignored: a test that needs a context
// to interrupt the stream uses net.Pipe inside a synctest bubble instead.
type scriptConn struct {
	mu  sync.Mutex
	src io.Reader

	readErr  error
	writeErr error

	// idle receives one token each time a Read finds src drained and has to
	// wait: every octet of the script has been consumed by then.
	idle chan struct{}

	done      chan struct{}
	closeOnce sync.Once
	closes    atomic.Int32
	written   atomic.Int64
}

func newScriptConn(src io.Reader) *scriptConn {
	return &scriptConn{src: src, idle: make(chan struct{}, 1), done: make(chan struct{})}
}

func (s *scriptConn) Read(p []byte) (int, error) {
	select {
	case <-s.done:
		return 0, net.ErrClosed
	default:
	}
	s.mu.Lock()
	n, err := s.src.Read(p)
	s.mu.Unlock()
	if n > 0 {
		return n, nil
	}
	if err == nil {
		return 0, io.ErrNoProgress
	}
	if s.readErr != nil {
		return 0, s.readErr
	}
	select {
	case s.idle <- struct{}{}:
	default:
	}
	<-s.done
	return 0, net.ErrClosed
}

func (s *scriptConn) Write(p []byte) (int, error) {
	select {
	case <-s.done:
		return 0, net.ErrClosed
	default:
	}
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.written.Add(int64(len(p)))
	return len(p), nil
}

func (s *scriptConn) Close() error {
	s.closes.Add(1)
	s.closeOnce.Do(func() { close(s.done) })
	return nil
}

func (s *scriptConn) LocalAddr() net.Addr              { return nil }
func (s *scriptConn) RemoteAddr() net.Addr             { return nil }
func (s *scriptConn) SetDeadline(time.Time) error      { return nil }
func (s *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (s *scriptConn) SetWriteDeadline(time.Time) error { return nil }

// awaitIdle waits until a Read has found the script drained.
func (s *scriptConn) awaitIdle(t *testing.T) {
	t.Helper()
	select {
	case <-s.idle:
	case <-time.After(30 * time.Second):
		t.Fatal("the reader did not consume the script and wait for more")
	}
}

// repeatReader returns unit n times and then io.EOF, without holding the
// whole stream in memory.
type repeatReader struct {
	unit []byte
	n    int
	off  int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		return 0, io.EOF
	}
	c := copy(p, r.unit[r.off:])
	r.off += c
	if r.off == len(r.unit) {
		r.off = 0
		r.n--
	}
	return c, nil
}

// openScriptConn returns an open Conn over sc, as Connect and Accept build
// it (metered stream, TPKT reader and writer), with its own reference
// allocator so a test can count releases.
func openScriptConn(t *testing.T, sc net.Conn, maxTPDU, maxTSDU int) (*Conn, *referenceAllocator) {
	t.Helper()
	stream := newMeteredConn(sc)
	reader, err := tpkt.NewReader(stream, tpkt.ReaderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := tpkt.NewWriter(stream)
	if err != nil {
		t.Fatal(err)
	}
	refs := newReferenceAllocator()
	ref, err := refs.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	c := newOpenConn(stream, reader, writer, NegotiatedParameters{
		Class: Class0, MaxTPDULength: maxTPDU, LocalRef: ref, RemoteRef: 2,
	}, maxTSDU, SizeProfileRFC1006Compat, ref, refs)
	return c, refs
}
