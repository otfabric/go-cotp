// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
)

// Minimal Class 0 DT overhead: LI (1) + type (1) + TPDU-NR/EOT (1).
const minimalDTOverhead = 3

// minNegotiatedTPDULength is the internal floor that allows at least one data octet
// in a minimal Class 0 DT (LI=2). TP0 negotiation already bottoms out at 128.
const minNegotiatedTPDULength = minimalDTOverhead + 1

// WriteTSDU sends one complete TSDU as one or more minimal Class 0 DT segments.
// Empty or locally oversized TSDUs are rejected before protocol I/O.
//
// Concurrent writers are serialized for the entire segmented transfer, so
// segments of different TSDUs never interleave; a writer waiting its turn
// returns ctx.Err() if ctx ends first. ctx bounds only the write direction
// (SetWriteDeadline); a concurrent ReadTSDU is unaffected. If ctx ends the
// write before any octet of the TSDU reached the stream, WriteTSDU returns
// ctx.Err() and the connection stays open; once octets have moved, the stream
// may hold a partial TSDU and the connection is aborted.
func (c *Conn) WriteTSDU(ctx context.Context, tsdu []byte) error {
	if c == nil {
		return fmt.Errorf("%w", ErrNilReceiver)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.writeMu == nil {
		// Not built by Connect or Accept: there is no stream to write.
		return fmt.Errorf("%w", ErrClosed)
	}

	if err := c.writeMu.lock(ctx); err != nil {
		return err
	}
	defer c.writeMu.unlock()

	if err := c.requireOpen(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateWriteTSDULength(len(tsdu), c.maxTSDU); err != nil {
		return err
	}
	maxSeg := maxSegmentPayload(c.negotiated.MaxTPDULength)
	if maxSeg < 1 {
		return fmt.Errorf("negotiated MaxTPDULength %d < %d: %w", c.negotiated.MaxTPDULength, minNegotiatedTPDULength, ErrInvalidConfig)
	}

	disarm, err := c.writeDeadline.arm(ctx)
	if err != nil {
		return err
	}
	defer disarm()

	start, tracked := c.writeProgress()
	for offset := 0; offset < len(tsdu); {
		end := min(offset+maxSeg, len(tsdu))
		chunk := tsdu[offset:end]
		eot := end == len(tsdu)
		payload, err := (&DT{EOT: eot, UserData: chunk}).MarshalBinary()
		if err != nil {
			return c.abort(err)
		}
		if err := c.writer.WritePacket(payload); err != nil {
			if n, ok := c.writeProgress(); tracked && ok && n == start {
				if cerr := c.idleTimeout(ctx, err); cerr != nil {
					return cerr
				}
			}
			return c.classifyIO(ctx, err)
		}
		offset = end
	}
	return nil
}

// ReadTSDU receives one complete TSDU by reassembling minimal Class 0 DT segments
// until EOT=1. The returned slice is the caller's: it has no capacity beyond
// its length, go-cotp keeps no reference to it, and a later call never
// changes it.
//
// One reader at a time reassembles a TSDU; a concurrent caller waits its turn
// and returns ctx.Err() if ctx ends first. ctx bounds only the read direction
// (SetReadDeadline); a concurrent WriteTSDU is unaffected. If ctx ends the
// read before any octet of the TSDU arrived, ReadTSDU returns ctx.Err() and
// the connection stays open; once octets have been consumed, the connection
// is aborted.
//
// Memory: the segments received so far are held in one buffer, whatever
// their size and number. Its capacity never exceeds MaxTSDULength; while it
// grows, and when the result is handed over, the old and the new buffer exist
// together, so a call holds less than twice MaxTSDULength, plus the TPKT
// packet being read (at most 65535 octets). A partly received TSDU is held
// until the call returns: until the final segment arrives, ctx ends, the
// stream fails or the connection is closed. A read loop without a deadline
// keeps it for as long as the peer leaves the TSDU unfinished.
func (c *Conn) ReadTSDU(ctx context.Context) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("%w", ErrNilReceiver)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.readMu == nil {
		// Not built by Connect or Accept: there is no stream to read.
		return nil, fmt.Errorf("%w", ErrClosed)
	}

	if err := c.readMu.lock(ctx); err != nil {
		return nil, err
	}
	defer c.readMu.unlock()

	if err := c.requireOpen(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.negotiated.MaxTPDULength < minNegotiatedTPDULength {
		return nil, fmt.Errorf("negotiated MaxTPDULength %d < %d: %w", c.negotiated.MaxTPDULength, minNegotiatedTPDULength, ErrInvalidConfig)
	}

	maxTSDU := c.maxTSDU
	if maxTSDU == 0 {
		maxTSDU = DefaultMaxTSDULength
	}

	disarm, err := c.readDeadline.arm(ctx)
	if err != nil {
		return nil, err
	}
	defer disarm()

	start, tracked := c.readProgress()
	// buf holds the user data of the segments accepted so far. Every accepted
	// segment carries at least one octet, so len(buf) > 0 means mid-TSDU.
	var buf []byte

	for {
		payload, err := c.reader.ReadPacket()
		if err != nil {
			if n, ok := c.readProgress(); tracked && ok && n == start {
				if cerr := c.idleTimeout(ctx, err); cerr != nil {
					return nil, cerr
				}
			}
			return nil, c.classifyIOPhase(ctx, err, len(buf) > 0)
		}

		mid := len(buf) > 0
		dt, err := decodeOpenDT(payload, c.negotiated.MaxTPDULength)
		if err != nil {
			return nil, c.abortOpen(mid, err)
		}
		seg := dt.UserData
		if len(seg) == 0 {
			// Empty DT segments are nonproductive and rejected in P1.
			return nil, c.abortOpen(mid, fmt.Errorf("empty DT segment: %w", ErrHandshake))
		}
		if len(seg) > maxTSDU-len(buf) {
			return nil, c.abortOpen(mid, fmt.Errorf("reassembly length %d > %d: %w", len(buf)+len(seg), maxTSDU, ErrTSDUTooLarge))
		}

		buf = appendSegment(buf, seg, maxTSDU)
		if dt.EOT {
			break
		}
	}
	return ownedTSDU(buf), nil
}

// appendSegment appends seg to the reassembly buffer buf. The buffer grows by
// doubling, never beyond limit octets of capacity, so the memory of a
// reassembly follows the octets received and not the number of segments.
// The caller has checked len(buf)+len(seg) <= limit.
func appendSegment(buf, seg []byte, limit int) []byte {
	need := len(buf) + len(seg)
	if need <= cap(buf) {
		return append(buf, seg...)
	}
	newCap := cap(buf)
	if newCap > limit-newCap {
		newCap = limit
	} else {
		newCap *= 2
	}
	if newCap < need {
		newCap = need
	}
	grown := make([]byte, len(buf), newCap)
	copy(grown, buf)
	return append(grown, seg...)
}

// ownedTSDU returns the reassembled TSDU for the caller: buf itself, clipped
// to its length, or a copy of exactly its length when more than a quarter of
// buf would stay allocated unused behind it.
func ownedTSDU(buf []byte) []byte {
	if cap(buf)-len(buf) > len(buf)/4 {
		out := make([]byte, len(buf))
		copy(out, buf)
		return out
	}
	return buf[:len(buf):len(buf)]
}

// peerGone reports whether err means the stream itself is gone (reset, broken
// pipe, closed underneath go-cotp, EOF inside a packet, or the kernel giving
// up on the connection), as opposed to a framing or protocol error.
func peerGone(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) ||
		connTimedOut(err) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe)
}

func maxSegmentPayload(maxTPDU int) int {
	if maxTPDU < minNegotiatedTPDULength {
		return 0
	}
	return maxTPDU - minimalDTOverhead
}

func (c *Conn) requireOpen() error {
	if kind := c.terminalKind(); kind != terminalNone {
		return c.terminalError()
	}
	if connState(c.state.Load()) != stateOpen {
		return fmt.Errorf("%w", ErrClosed)
	}
	return nil
}

// idleTimeout returns ctx's error when err is the stream deadline that ctx
// armed and no octet of the operation has crossed the stream, so the
// connection is still at a packet boundary and stays open. It returns nil
// when err must be classified (and the connection aborted) as usual.
func (c *Conn) idleTimeout(ctx context.Context, err error) error {
	if c.terminalKind() != terminalNone || !isTimeout(err) {
		return nil
	}
	return ctxDoneErr(ctx)
}

func (c *Conn) classifyIO(ctx context.Context, err error) error {
	return c.classifyIOPhase(ctx, err, false)
}

// classifyIOPhase maps an underlying I/O error after protocol I/O has started.
// midTSDU selects incomplete-TSDU classification for reassembly failures.
func (c *Conn) classifyIOPhase(ctx context.Context, err error, midTSDU bool) error {
	if err == nil {
		return nil
	}
	if c.terminalKind() != terminalNone {
		return c.terminalError()
	}
	// A connection timeout reported by the kernel is the stream going away,
	// whatever state ctx is in: it is classified below, with peerGone.
	if !connTimedOut(err) {
		if ctx.Err() != nil {
			return c.abort(fmt.Errorf("%w: %w", ErrClosed, ctx.Err()))
		}
		if _, ok := ctx.Deadline(); ok && isTimeout(err) {
			return c.abort(fmt.Errorf("%w: %w", ErrClosed, context.DeadlineExceeded))
		}
	}
	if errors.Is(err, io.EOF) {
		if midTSDU {
			return c.abort(errors.Join(ErrIncompleteTSDU, &DisconnectError{Cause: io.EOF}))
		}
		return c.abort(&DisconnectError{Cause: io.EOF})
	}
	if peerGone(err) {
		if midTSDU || errors.Is(err, io.ErrUnexpectedEOF) {
			return c.abort(errors.Join(ErrIncompleteTSDU, &DisconnectError{Cause: err}))
		}
		return c.abort(&DisconnectError{Cause: err})
	}
	if isFramingError(err) {
		// A protocol violation by the peer, reported like a malformed DT.
		return c.abortOpen(midTSDU, fmt.Errorf("%w: %w", ErrHandshake, err))
	}
	if midTSDU {
		return c.abort(errors.Join(ErrIncompleteTSDU, &DisconnectError{Cause: err}))
	}
	return c.abort(err)
}
