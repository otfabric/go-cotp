// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/otfabric/go-tpkt"
)

type connState uint8

const (
	stateConnecting connState = iota
	stateAccepting
	stateOpen
	stateClosing
	stateClosed
	stateAborted
)

type terminalKind uint8

const (
	terminalNone terminalKind = iota
	terminalClosed
	terminalAborted
)

// Conn is an established Class 0 (TP0) COTP connection over a stream.
type Conn struct {
	raw    net.Conn
	reader *tpkt.Reader
	writer *tpkt.Writer

	// readMu and writeMu serialize each direction for a whole TSDU, so
	// segments of different TSDUs never interleave. They are channel locks
	// so that a caller queued behind a long transfer still honours its ctx.
	readMu  opLock
	writeMu opLock

	// readDeadline and writeDeadline apply a TSDU operation's context to
	// its own direction only.
	readDeadline  *directionDeadline
	writeDeadline *directionDeadline

	// metered counts octets per direction; nil when raw is not a
	// *meteredConn (some unit tests), in which case progress is unknown.
	metered *meteredConn

	negotiated NegotiatedParameters
	maxTSDU    int
	profile    SizeProfile

	localRef uint16
	refs     *referenceAllocator

	state atomic.Uint32 // connState

	termOnce sync.Once
	termKind terminalKind
	termErr  error
	termMu   sync.Mutex // protects termKind/termErr reads after Once

	refOnce sync.Once
}

var defaultRefs = newReferenceAllocator()

func newOpenConn(
	raw net.Conn,
	reader *tpkt.Reader,
	writer *tpkt.Writer,
	neg NegotiatedParameters,
	maxTSDU int,
	profile SizeProfile,
	localRef uint16,
	refs *referenceAllocator,
) *Conn {
	c := &Conn{
		raw:        raw,
		reader:     reader,
		writer:     writer,
		negotiated: neg,
		maxTSDU:    maxTSDU,
		profile:    profile,
		localRef:   localRef,
		refs:       refs,
		readMu:     newOpLock(),
		writeMu:    newOpLock(),
	}
	if raw != nil {
		c.readDeadline = newDirectionDeadline(raw.SetReadDeadline)
		c.writeDeadline = newDirectionDeadline(raw.SetWriteDeadline)
	}
	c.metered, _ = raw.(*meteredConn)
	c.state.Store(uint32(stateOpen))
	return c
}

// Negotiated returns a copy of the frozen handshake parameters.
func (c *Conn) Negotiated() NegotiatedParameters {
	if c == nil {
		return NegotiatedParameters{}
	}
	n := c.negotiated
	n.LocalSelector = copyBytes(n.LocalSelector)
	n.RemoteSelector = copyBytes(n.RemoteSelector)
	n.PeerConnectData = copyBytes(n.PeerConnectData)
	return n
}

// LocalAddr returns the local network address, or nil.
func (c *Conn) LocalAddr() net.Addr {
	if c == nil || c.raw == nil {
		return nil
	}
	return c.raw.LocalAddr()
}

// RemoteAddr returns the remote network address, or nil.
func (c *Conn) RemoteAddr() net.Addr {
	if c == nil || c.raw == nil {
		return nil
	}
	return c.raw.RemoteAddr()
}

// Close performs the TP0 T-DISCONNECT operation by closing the underlying stream.
// It is idempotent on a non-nil Conn. Nil-receiver Close is not promised.
func (c *Conn) Close() error {
	if c == nil {
		return fmt.Errorf("%w", ErrNilReceiver)
	}
	return c.finish(terminalClosed, ErrClosed)
}

func (c *Conn) finish(kind terminalKind, err error) error {
	c.termOnce.Do(func() {
		c.termMu.Lock()
		c.termKind = kind
		c.termErr = err
		c.termMu.Unlock()
		if kind == terminalClosed {
			c.state.Store(uint32(stateClosing))
		} else {
			c.state.Store(uint32(stateAborted))
		}
		if c.raw != nil {
			_ = c.raw.Close()
		}
		c.releaseRef()
		if kind == terminalClosed {
			c.state.Store(uint32(stateClosed))
		}
	})
	return c.terminalError()
}

func (c *Conn) releaseRef() {
	c.refOnce.Do(func() {
		if c.refs != nil && c.localRef != 0 {
			c.refs.Release(c.localRef)
		}
	})
}

func (c *Conn) terminalError() error {
	c.termMu.Lock()
	defer c.termMu.Unlock()
	if c.termKind == terminalNone {
		return nil
	}
	return c.termErr
}

func (c *Conn) terminalKind() terminalKind {
	c.termMu.Lock()
	defer c.termMu.Unlock()
	return c.termKind
}

// abort records an aborted terminal cause if none is set yet, closes the stream,
// and returns the stored terminal error (first cause wins).
func (c *Conn) abort(err error) error {
	if err == nil {
		err = ErrClosed
	}
	_ = c.finish(terminalAborted, err)
	return c.terminalError()
}

// opLock is a mutex whose Lock gives up when ctx is done.
type opLock chan struct{}

func newOpLock() opLock { return make(opLock, 1) }

func (l opLock) lock(ctx context.Context) error {
	select {
	case l <- struct{}{}:
		return nil
	default:
	}
	select {
	case l <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l opLock) unlock() { <-l }

// readProgress and writeProgress return the octets moved so far in each
// direction, and false when that is not tracked.
func (c *Conn) readProgress() (int64, bool) {
	if c.metered == nil {
		return 0, false
	}
	return c.metered.nRead.Load(), true
}

func (c *Conn) writeProgress() (int64, bool) {
	if c.metered == nil {
		return 0, false
	}
	return c.metered.nWritten.Load(), true
}

// armHandshake applies ctx to both directions of conn for the single-goroutine
// connect/accept handshake, the only phase that uses conn.SetDeadline.
func armHandshake(conn net.Conn, ctx context.Context) (disarm func(), err error) {
	if conn == nil {
		return func() {}, fmt.Errorf("%w", ErrInvalidConfig)
	}
	return newDirectionDeadline(conn.SetDeadline).arm(ctx)
}
