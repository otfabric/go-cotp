// SPDX-License-Identifier: MIT

package cotp

import "context"

// Class is an X.224 transport protocol class.
type Class uint8

const Class0 Class = 0

// ClientConfig configures the initiating TP0/ITOT handshake (Connect).
type ClientConfig struct {
	LocalSelector  []byte
	RemoteSelector []byte
	MaxTPDULength  int
	MaxTSDULength  int
	ConnectData    []byte
	SizeProfile    SizeProfile
}

// ServerConfig configures the responding TP0/ITOT handshake (Accept).
type ServerConfig struct {
	// LocalSelector default accept policy:
	//   nil            → no called-selector requirement
	//   non-nil empty  → CR must present CalledSelector of length 0
	//   non-empty      → CR must present CalledSelector equal exactly
	LocalSelector []byte
	MaxTPDULength int
	MaxTSDULength int
	// OnConnect decides accept/reject. Nil = defaultAutoAccept.
	// Indication fields are defensive copies (safe to retain).
	OnConnect   func(context.Context, ConnectIndication) (AcceptDecision, error)
	SizeProfile SizeProfile
	// EchoSelectors returns the CR's transport selectors in the CC
	// (X.224 §13.3.4: "If a Transport-Selector is given in the request it
	// may be returned in the confirmation"): the calling selector as 0xC1
	// and, as the responding selector 0xC2, LocalSelector when non-nil,
	// otherwise the CR's called selector. A selector absent from the CR
	// stays absent. False (the default) sends only LocalSelector, as before.
	EchoSelectors bool
}

// ConnectIndication is presented to server connection policy.
// All slices are defensive copies.
type ConnectIndication struct {
	CallingSelector []byte
	CalledSelector  []byte
	ProposedClass   Class
	// MaxTPDULength is the ceiling presented to policy (preferred offer when present).
	MaxTPDULength int
	ConnectData   []byte
	SourceRef     uint16
}

// AcceptDecision is the policy result for a connection indication.
type AcceptDecision struct {
	Action ConnectAction
	// MaxTPDULength is an additional policy ceiling when non-zero.
	MaxTPDULength int
	ConnectData   []byte
	RejectReason  DisconnectReason // meaningful only when Action == ConnectReject
}

// NegotiatedParameters are frozen after a successful CR/CC handshake.
// All slices are defensive copies. Selector nil means absent; non-nil empty means present len 0.
// On the client RemoteSelector is the CC's responding selector when the CC
// carries one (it may differ from ClientConfig.RemoteSelector), otherwise
// the requested one; on the server LocalSelector is the responding selector
// sent in the CC and RemoteSelector the CR's calling selector.
type NegotiatedParameters struct {
	Class           Class
	MaxTPDULength   int
	LocalRef        uint16
	RemoteRef       uint16
	LocalSelector   []byte
	RemoteSelector  []byte
	PeerConnectData []byte
}

func (cfg ClientConfig) preflight() (maxTPDU, maxTSDU int, err error) {
	if err := validateSizeProfile(cfg.SizeProfile); err != nil {
		return 0, 0, err
	}
	maxTPDU, err = normalizeConfiguredMax(cfg.MaxTPDULength)
	if err != nil {
		return 0, 0, err
	}
	if err := validateMaxTSDULength(cfg.MaxTSDULength); err != nil {
		return 0, 0, err
	}
	maxTSDU = cfg.MaxTSDULength
	if maxTSDU == 0 {
		maxTSDU = DefaultMaxTSDULength
	}
	if err := validateSelectorLength(cfg.LocalSelector, "LocalSelector"); err != nil {
		return 0, 0, err
	}
	if err := validateSelectorLength(cfg.RemoteSelector, "RemoteSelector"); err != nil {
		return 0, 0, err
	}
	if err := validateConnectDataLength(cfg.ConnectData); err != nil {
		return 0, 0, err
	}
	return maxTPDU, maxTSDU, nil
}

func (cfg ServerConfig) preflight() (maxTPDU, maxTSDU int, err error) {
	if err := validateSizeProfile(cfg.SizeProfile); err != nil {
		return 0, 0, err
	}
	maxTPDU, err = normalizeConfiguredMax(cfg.MaxTPDULength)
	if err != nil {
		return 0, 0, err
	}
	if err := validateMaxTSDULength(cfg.MaxTSDULength); err != nil {
		return 0, 0, err
	}
	maxTSDU = cfg.MaxTSDULength
	if maxTSDU == 0 {
		maxTSDU = DefaultMaxTSDULength
	}
	if err := validateSelectorLength(cfg.LocalSelector, "LocalSelector"); err != nil {
		return 0, 0, err
	}
	return maxTPDU, maxTSDU, nil
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func closeConn(conn interface{ Close() error }) {
	if conn != nil {
		_ = conn.Close()
	}
}
