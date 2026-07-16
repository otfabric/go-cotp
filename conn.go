// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

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

	readMu  sync.Mutex
	writeMu sync.Mutex

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
	}
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

// armDeadline sets the connection deadline from ctx. The returned clear function
// must be called when the logical operation ends. If ctx is cancelled without a
// deadline while waiters may be blocked, clear still restores the deadline.
//
// Protocol I/O is considered started once the caller invokes an underlying
// Read/Write/ReadPacket/WritePacket after arming.
func armDeadline(conn net.Conn, ctx context.Context) (clear func(), err error) {
	if conn == nil {
		return func() {}, fmt.Errorf("%w", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return func() {}, err
	}
	var stopWatch chan struct{}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		stopWatch = make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.SetDeadline(time.Unix(1, 0))
			case <-stopWatch:
			}
		}()
	}
	var once sync.Once
	clear = func() {
		once.Do(func() {
			if stopWatch != nil {
				close(stopWatch)
			}
			_ = conn.SetDeadline(time.Time{})
		})
	}
	return clear, nil
}
