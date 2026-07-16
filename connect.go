// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/otfabric/go-tpkt"
)

// Connect performs the initiating TP0/ITOT handshake on conn.
//
// Ownership of conn transfers immediately. On any error, conn is closed and
// must not be used further. On success, the returned Conn owns the stream.
func Connect(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Conn, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: nil conn", ErrInvalidConfig)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// Immediate ownership: every exit path except success closes conn.
	success := false
	defer func() {
		if !success {
			closeConn(conn)
		}
	}()

	maxTPDU, maxTSDU, err := cfg.preflight()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	reader, err := tpkt.NewReader(conn, tpkt.ReaderConfig{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	writer, err := tpkt.NewWriter(conn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	refs := defaultRefs
	localRef, err := refs.Allocate()
	if err != nil {
		return nil, err
	}
	refHeld := true
	defer func() {
		if refHeld {
			refs.Release(localRef)
		}
	}()

	offer, err := buildSizeOffer(maxTPDU, cfg.SizeProfile)
	if err != nil {
		return nil, err
	}

	cr := &CR{
		CDT:                  0,
		DestinationRef:       0,
		SourceRef:            localRef,
		ClassOption:          0,
		CallingSelector:      copyBytes(cfg.LocalSelector),
		CalledSelector:       copyBytes(cfg.RemoteSelector),
		TPDUSize:             offer.StandardCode,
		PreferredMaxTPDUSize: offer.PreferredUnits,
		UserData:             copyBytes(cfg.ConnectData),
	}
	crBytes, err := cr.MarshalBinary()
	if err != nil {
		// Local encode failure (e.g. CR > 128) is configuration, before I/O.
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	clear, err := armDeadline(conn, ctx)
	if err != nil {
		return nil, err
	}
	defer clear()

	if err := writer.WritePacket(crBytes); err != nil {
		return nil, connectIOError(ctx, err)
	}
	payload, err := reader.ReadPacket()
	if err != nil {
		return nil, connectIOError(ctx, err)
	}

	decoded, err := Decode(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}

	switch decoded.Type {
	case TypeDR:
		return nil, rejectionFromDR(decoded.DR)
	case TypeER:
		cause := uint8(0)
		if decoded.ER != nil {
			cause = decoded.ER.RejectCause
		}
		return nil, fmt.Errorf("ER reject cause %d: %w", cause, ErrHandshake)
	case TypeCC:
		// continue
	default:
		return nil, &UnexpectedTPDUError{Type: decoded.Type, Phase: PhaseHandshake}
	}

	cc := decoded.CC
	if cc == nil {
		return nil, fmt.Errorf("nil CC: %w", ErrHandshake)
	}

	if err := validateClass0CCFixed(cc.CDT, cc.ClassOption); err != nil {
		return nil, err
	}
	if err := validateCCReferences(cc.DestinationRef, cc.SourceRef, localRef); err != nil {
		return nil, err
	}
	if err := validateCCParameters(cc.Parameters); err != nil {
		return nil, err
	}
	if err := validateClientCCSelector(cfg.RemoteSelector, cc.CalledSelector); err != nil {
		return nil, err
	}
	if len(cc.UserData) > MaxConnectDataLength {
		return nil, fmt.Errorf("CC connect data length %d > %d: %w", len(cc.UserData), MaxConnectDataLength, ErrHandshake)
	}

	effective, err := interpretCCSize(offer.Offer, cc.TPDUSize, cc.PreferredMaxTPDUSize, cfg.SizeProfile)
	if err != nil {
		return nil, err
	}

	remoteSelector := copyBytes(cfg.RemoteSelector)
	if cc.CalledSelector != nil {
		remoteSelector = copyBytes(cc.CalledSelector)
	}

	neg := NegotiatedParameters{
		Class:           Class0,
		MaxTPDULength:   effective,
		LocalRef:        localRef,
		RemoteRef:       cc.SourceRef,
		LocalSelector:   copyBytes(cfg.LocalSelector),
		RemoteSelector:  remoteSelector,
		PeerConnectData: copyBytes(cc.UserData),
	}

	c := newOpenConn(conn, reader, writer, neg, maxTSDU, cfg.SizeProfile, localRef, refs)
	refHeld = false
	success = true
	return c, nil
}

func rejectionFromDR(dr *DR) error {
	if dr == nil {
		return fmt.Errorf("%w", ErrConnectionRefused)
	}
	return &RejectionError{
		Reason: DisconnectReason(dr.Reason),
		Info:   copyBytes(dr.UserData),
	}
}

func connectIOError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %w", ErrClosed, ctx.Err())
	}
	// conn.SetDeadline and context timers are independent: the TCP deadline can
	// fire before ctx.Err() is set. Treat a timeout under a context deadline as
	// DeadlineExceeded, matching open-state classifyIOPhase.
	if _, ok := ctx.Deadline(); ok {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return fmt.Errorf("%w: %w", ErrClosed, context.DeadlineExceeded)
		}
	}
	if errors.Is(err, io.EOF) {
		return &DisconnectError{Cause: io.EOF}
	}
	return err
}
