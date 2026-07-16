// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"fmt"
	"net"

	"github.com/otfabric/go-tpkt"
)

// X.224 §13.12.2 ER reject-cause codes.
const (
	erCauseNotSpecified          uint8 = 0
	erCauseInvalidParameterCode  uint8 = 1
	erCauseInvalidTPDUType       uint8 = 2
	erCauseInvalidParameterValue uint8 = 3
)

// Accept performs the responding TP0/ITOT handshake on conn.
//
// Ownership of conn transfers immediately. On any error, conn is closed and
// must not be used further. On success, the returned Conn owns the stream.
func Accept(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Conn, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: nil conn", ErrInvalidConfig)
	}
	if ctx == nil {
		ctx = context.Background()
	}

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

	clear, err := armDeadline(conn, ctx)
	if err != nil {
		return nil, err
	}
	defer clear()

	payload, err := reader.ReadPacket()
	if err != nil {
		return nil, connectIOError(ctx, err)
	}

	decoded, err := Decode(payload)
	if err != nil {
		// Malformed / unassociable: close without fabricating a response.
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	if decoded.Type != TypeCR || decoded.CR == nil {
		return nil, &UnexpectedTPDUError{Type: decoded.Type, Phase: PhaseHandshake}
	}
	cr := decoded.CR

	preferredClass := Class(cr.ClassOption >> 4)
	optionBits := cr.ClassOption & 0x0F

	// Non-Class-0 preferred class: valid CR shape rejected by policy → DR.
	if preferredClass != Class0 {
		_ = writeDR(writer, cr.SourceRef, 0, ReasonNegotiationFailed)
		return nil, &RejectionError{Reason: ReasonNegotiationFailed}
	}

	// Identifiable Class 0 CR with protocol field errors → ER when associable.
	if cause, ok := class0CRProtocolError(cr, optionBits); ok {
		if cr.SourceRef == 0 {
			return nil, fmt.Errorf("unassociable Class 0 CR: %w", ErrHandshake)
		}
		_ = writeER(writer, cr.SourceRef, cause)
		return nil, fmt.Errorf("invalid Class 0 CR: %w", ErrHandshake)
	}

	peerOffer, err := decodeSizeOffer(cr.TPDUSize, cr.PreferredMaxTPDUSize)
	if err != nil {
		if cr.SourceRef == 0 {
			return nil, fmt.Errorf("unassociable Class 0 CR: %w", ErrHandshake)
		}
		_ = writeER(writer, cr.SourceRef, erCauseInvalidParameterValue)
		return nil, err
	}
	if len(cr.UserData) > MaxConnectDataLength {
		if cr.SourceRef == 0 {
			return nil, fmt.Errorf("unassociable Class 0 CR: %w", ErrHandshake)
		}
		_ = writeER(writer, cr.SourceRef, erCauseInvalidParameterValue)
		return nil, fmt.Errorf("CR connect data length %d > %d: %w", len(cr.UserData), MaxConnectDataLength, ErrHandshake)
	}

	ind := ConnectIndication{
		CallingSelector: copyBytes(cr.CallingSelector),
		CalledSelector:  copyBytes(cr.CalledSelector),
		ProposedClass:   preferredClass,
		MaxTPDULength:   indicationMaxTPDULength(peerOffer),
		ConnectData:     copyBytes(cr.UserData),
		SourceRef:       cr.SourceRef,
	}

	var decision AcceptDecision
	if cfg.OnConnect == nil {
		decision, err = defaultAutoAccept(cfg, ind)
	} else {
		decision, err = cfg.OnConnect(ctx, ind)
	}
	if err != nil {
		// Local callback failure: close; do not invent a DR reason.
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	if err := validateConnectAction(decision.Action); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	if decision.Action == ConnectReject {
		reason := decision.RejectReason // zero = ReasonNotSpecified
		_ = writeDR(writer, cr.SourceRef, 0, reason)
		return nil, &RejectionError{Reason: reason}
	}

	// ConnectAccept: RejectReason is ignored.
	if err := validateConnectDataLength(decision.ConnectData); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	if decision.MaxTPDULength != 0 {
		if _, err := normalizeConfiguredMax(decision.MaxTPDULength); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
		}
	}

	sel, err := selectSize(peerOffer, maxTPDU, decision.MaxTPDULength, cfg.SizeProfile)
	if err != nil {
		return nil, err
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

	cc := &CC{
		CDT:                  0,
		DestinationRef:       cr.SourceRef,
		SourceRef:            localRef,
		ClassOption:          0,
		CalledSelector:       copyBytes(cfg.LocalSelector), // nil → omit
		TPDUSize:             sel.StandardCode,
		PreferredMaxTPDUSize: sel.PreferredUnits,
		UserData:             copyBytes(decision.ConnectData),
	}
	ccBytes, err := cc.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	if err := writer.WritePacket(ccBytes); err != nil {
		return nil, connectIOError(ctx, err)
	}

	neg := NegotiatedParameters{
		Class:           Class0,
		MaxTPDULength:   sel.Effective,
		LocalRef:        localRef,
		RemoteRef:       cr.SourceRef,
		LocalSelector:   copyBytes(cfg.LocalSelector),
		RemoteSelector:  copyBytes(cr.CallingSelector),
		PeerConnectData: copyBytes(cr.UserData),
	}

	c := newOpenConn(conn, reader, writer, neg, maxTSDU, cfg.SizeProfile, localRef, refs)
	refHeld = false
	success = true
	return c, nil
}

func defaultAutoAccept(cfg ServerConfig, ind ConnectIndication) (AcceptDecision, error) {
	if ind.ProposedClass != Class0 {
		return AcceptDecision{Action: ConnectReject, RejectReason: ReasonNegotiationFailed}, nil
	}
	// Selector mismatch is a policy refuse (DR), not a local callback/config error.
	if err := validateServerCalledSelector(cfg.LocalSelector, ind.CalledSelector); err != nil {
		return AcceptDecision{Action: ConnectReject, RejectReason: ReasonAddressUnknown}, nil //nolint:nilerr
	}
	return AcceptDecision{Action: ConnectAccept}, nil
}

// class0CRProtocolError reports an ER reject cause for an identifiable Class 0 CR.
// ok is false when the CR has no Class 0 protocol-field error at this stage.
func class0CRProtocolError(cr *CR, optionBits uint8) (cause uint8, ok bool) {
	if cr.CDT != 0 || optionBits != 0 {
		return erCauseInvalidParameterValue, true
	}
	if cr.DestinationRef != 0 {
		return erCauseInvalidParameterValue, true
	}
	if cr.SourceRef == 0 {
		return erCauseInvalidParameterValue, true
	}
	for _, p := range cr.Parameters {
		if isKnownClass0ForbiddenParam(p.Code) {
			return erCauseInvalidParameterCode, true
		}
	}
	return 0, false
}

func writeDR(w *tpkt.Writer, dst, src uint16, reason DisconnectReason) error {
	b, err := (&DR{
		DestinationRef: dst,
		SourceRef:      src,
		Reason:         uint8(reason),
	}).MarshalBinary()
	if err != nil {
		return err
	}
	return w.WritePacket(b)
}

func writeER(w *tpkt.Writer, dst uint16, cause uint8) error {
	b, err := (&ER{
		DestinationRef: dst,
		RejectCause:    cause,
	}).MarshalBinary()
	if err != nil {
		return err
	}
	return w.WritePacket(b)
}
