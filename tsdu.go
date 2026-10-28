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
		end := offset + maxSeg
		if end > len(tsdu) {
			end = len(tsdu)
		}
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
// until EOT=1. The returned slice is caller-owned and does not alias internal buffers.
//
// One reader at a time reassembles a TSDU; a concurrent caller waits its turn
// and returns ctx.Err() if ctx ends first. ctx bounds only the read direction
// (SetReadDeadline); a concurrent WriteTSDU is unaffected. If ctx ends the
// read before any octet of the TSDU arrived, ReadTSDU returns ctx.Err() and
// the connection stays open; once octets have been consumed, the connection
// is aborted.
func (c *Conn) ReadTSDU(ctx context.Context) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("%w", ErrNilReceiver)
	}
	if ctx == nil {
		ctx = context.Background()
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
	segments := make([][]byte, 0, 4)
	total := 0

	for {
		payload, err := c.reader.ReadPacket()
		if err != nil {
			if n, ok := c.readProgress(); tracked && ok && n == start {
				if cerr := c.idleTimeout(ctx, err); cerr != nil {
					return nil, cerr
				}
			}
			return nil, c.classifyIOPhase(ctx, err, len(segments) > 0)
		}

		mid := len(segments) > 0
		dt, err := decodeOpenDT(payload, c.negotiated.MaxTPDULength)
		if err != nil {
			return nil, c.abortOpen(mid, err)
		}
		seg := dt.UserData
		if len(seg) == 0 {
			// Empty DT segments are nonproductive and rejected in P1.
			return nil, c.abortOpen(mid, fmt.Errorf("empty DT segment: %w", ErrHandshake))
		}
		if total+len(seg) > maxTSDU {
			return nil, c.abortOpen(mid, fmt.Errorf("reassembly length %d > %d: %w", total+len(seg), maxTSDU, ErrTSDUTooLarge))
		}
		// Defensive segment-count bound: each accepted segment carries ≥1 byte.
		if len(segments)+1 > maxTSDU {
			return nil, c.abortOpen(mid, fmt.Errorf("segment count %d > %d: %w", len(segments)+1, maxTSDU, ErrTSDUTooLarge))
		}

		segments = append(segments, copyBytes(seg))
		total += len(seg)
		if dt.EOT {
			break
		}
	}

	out := make([]byte, total)
	off := 0
	for _, s := range segments {
		copy(out[off:], s)
		off += len(s)
	}
	return out, nil
}

// peerGone reports whether err means the stream itself is gone (reset, broken
// pipe, closed underneath go-cotp, or EOF inside a packet), as opposed to a
// framing or protocol error.
func peerGone(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) ||
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
	if ctx.Err() != nil {
		return c.abort(fmt.Errorf("%w: %w", ErrClosed, ctx.Err()))
	}
	if _, ok := ctx.Deadline(); ok && isTimeout(err) {
		return c.abort(fmt.Errorf("%w: %w", ErrClosed, context.DeadlineExceeded))
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
	if midTSDU {
		return c.abort(errors.Join(ErrIncompleteTSDU, &DisconnectError{Cause: err}))
	}
	return c.abort(err)
}
