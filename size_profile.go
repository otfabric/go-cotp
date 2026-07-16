// SPDX-License-Identifier: MIT

package cotp

// SizeProfile selects local CR/CC size-parameter encoding and how omitted
// peer selections are interpreted for the TP0/ITOT service layer.
type SizeProfile int

const (
	// SizeProfileRFC1006Compat: installed-base CR/CC omission rules;
	// accept legacy and preferred CRs; respond based on what the peer proposed.
	SizeProfileRFC1006Compat SizeProfile = iota
	// SizeProfilePreferredMaximum: always propose 0xF0 (with 0xC0 fallback);
	// require explicit selected-size on incoming CC; still decode legacy CR.
	SizeProfilePreferredMaximum
)

// TP0/ITOT service constants (not generic codec limits).
const (
	DefaultMaxTPDULength  = 65531
	DefaultMaxTSDULength  = 4 * 1024 * 1024
	MaxITOTTPDULength     = 65531
	MinTPDULength         = 128
	MaxPreferredUnitsITOT = 511
	MaxConnectDataLength  = 32
)

// DisconnectReason is an X.224 DR reason code (X.224 §13.5.3).
type DisconnectReason uint8

const (
	ReasonNotSpecified       DisconnectReason = 0
	ReasonCongestionAtTSAP   DisconnectReason = 1
	ReasonSessionNotAttached DisconnectReason = 2
	ReasonAddressUnknown     DisconnectReason = 3
)

const (
	ReasonNormalDisconnect         DisconnectReason = 128
	ReasonRemoteCongestion         DisconnectReason = 129
	ReasonNegotiationFailed        DisconnectReason = 130
	ReasonDuplicateSourceReference DisconnectReason = 131
	ReasonMismatchedReferences     DisconnectReason = 132
	ReasonProtocolError            DisconnectReason = 133
	ReasonReferenceOverflow        DisconnectReason = 135
	ReasonRefusedOnNetworkConn     DisconnectReason = 136
	ReasonInvalidHeaderOrParamLen  DisconnectReason = 138
)

// ConnectAction is the accept/reject decision for a connection indication.
type ConnectAction uint8

const (
	ConnectReject ConnectAction = iota
	ConnectAccept
)
