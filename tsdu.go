// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
)

// Minimal Class 0 DT overhead: LI (1) + type (1) + TPDU-NR/EOT (1).
const minimalDTOverhead = 3

// minNegotiatedTPDULength is the internal floor that allows at least one data octet
// in a minimal Class 0 DT (LI=2). TP0 negotiation already bottoms out at 128.
const minNegotiatedTPDULength = minimalDTOverhead + 1

// WriteTSDU sends one complete TSDU as one or more minimal Class 0 DT segments.
// Empty or locally oversized TSDUs are rejected before protocol I/O.
// writeMu is held for the entire segmented transfer.
func (c *Conn) WriteTSDU(ctx context.Context, tsdu []byte) error {
	if c == nil {
		return fmt.Errorf("%w", ErrNilReceiver)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

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

	clear, err := armDeadline(c.raw, ctx)
	if err != nil {
		return err
	}
	defer clear()

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
			return c.classifyIO(ctx, err)
		}
		offset = end
	}
	return nil
}

// ReadTSDU receives one complete TSDU by reassembling minimal Class 0 DT segments
// until EOT=1. The returned slice is caller-owned and does not alias internal buffers.
// readMu is held for the entire reassembly operation.
func (c *Conn) ReadTSDU(ctx context.Context) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("%w", ErrNilReceiver)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

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

	clear, err := armDeadline(c.raw, ctx)
	if err != nil {
		return nil, err
	}
	defer clear()

	segments := make([][]byte, 0, 4)
	total := 0

	for {
		payload, err := c.reader.ReadPacket()
		if err != nil {
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
	if _, ok := ctx.Deadline(); ok {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return c.abort(fmt.Errorf("%w: %w", ErrClosed, context.DeadlineExceeded))
		}
	}
	if errors.Is(err, io.EOF) {
		if midTSDU {
			return c.abort(errors.Join(ErrIncompleteTSDU, &DisconnectError{Cause: io.EOF}))
		}
		return c.abort(&DisconnectError{Cause: io.EOF})
	}
	if midTSDU {
		return c.abort(errors.Join(ErrIncompleteTSDU, &DisconnectError{Cause: err}))
	}
	return c.abort(err)
}
