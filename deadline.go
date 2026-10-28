// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// pastDeadline is the deadline set to interrupt a blocked operation when its
// context is cancelled.
var pastDeadline = time.Unix(1, 0)

// directionDeadline applies one context at a time to one direction of the
// stream (read, write, or both during the handshake) through set.
//
// net.Conn deadlines are per direction: an operation in one direction must
// only touch that direction's deadline, or a write that arms and clears its
// deadline would cut or extend a concurrent read. Between operations the
// direction's deadline is restored to base (the zero time: none).
//
// Operations on one directionDeadline are serialized by the caller (readMu,
// writeMu, or the single-goroutine handshake). mu orders the cancellation
// callback against disarm, so a cancel that races the end of an operation
// can never leave a past deadline behind for the next one.
type directionDeadline struct {
	set func(time.Time) error

	mu     sync.Mutex
	active uint64 // generation of the armed operation; 0 when idle
	gen    uint64
}

func newDirectionDeadline(set func(time.Time) error) *directionDeadline {
	return &directionDeadline{set: set}
}

// arm applies ctx's deadline, and an immediate deadline when ctx is
// cancelled, to the direction. The returned disarm function stops the
// cancellation callback and restores the direction's base deadline; it is
// idempotent. If ctx is already done, arm returns ctx.Err() and changes
// nothing.
func (d *directionDeadline) arm(ctx context.Context) (disarm func(), err error) {
	if err := ctx.Err(); err != nil {
		return func() {}, err
	}
	d.mu.Lock()
	d.gen++
	g := d.gen
	d.active = g
	if dl, ok := ctx.Deadline(); ok {
		_ = d.set(dl)
	}
	d.mu.Unlock()

	stop := func() bool { return true }
	if ctx.Done() != nil {
		stop = context.AfterFunc(ctx, func() {
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.active == g {
				_ = d.set(pastDeadline)
			}
		})
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			stop()
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.active == g {
				d.active = 0
				_ = d.set(time.Time{})
			}
		})
	}, nil
}

// meteredConn counts the octets that crossed the stream in each direction,
// so a context that ends an operation before any octet moved can be reported
// without aborting the connection: the stream is still at a packet boundary.
type meteredConn struct {
	net.Conn
	nRead    atomic.Int64
	nWritten atomic.Int64
}

func newMeteredConn(c net.Conn) *meteredConn {
	return &meteredConn{Conn: c}
}

func (m *meteredConn) Read(p []byte) (int, error) {
	n, err := m.Conn.Read(p)
	if n > 0 {
		m.nRead.Add(int64(n))
	}
	return n, err
}

func (m *meteredConn) Write(p []byte) (int, error) {
	n, err := m.Conn.Write(p)
	if n > 0 {
		m.nWritten.Add(int64(n))
	}
	return n, err
}

// ctxDoneErr returns ctx.Err(), or context.DeadlineExceeded once ctx's
// deadline has passed even if its timer has not fired yet: the stream
// deadline taken from ctx and ctx's own timer are independent.
func ctxDoneErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
		return context.DeadlineExceeded
	}
	return nil
}

// isTimeout reports whether err is a stream deadline expiry.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
