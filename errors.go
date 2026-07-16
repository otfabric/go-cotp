// SPDX-License-Identifier: MIT

package cotp

import "errors"

// Sentinel errors for decode/encode. Callers should use errors.Is to classify.
// Decode/encode functions wrap these with context (e.g. "decode CR: %w").
var (
	// ErrTooShort indicates the buffer is shorter than required (e.g. no LI or type code).
	ErrTooShort = errors.New("cotp: buffer too short")
	// ErrInvalidLI indicates the length indicator is invalid (e.g. > 254, or shorter than the TPDU fixed part).
	ErrInvalidLI = errors.New("cotp: invalid length indicator")
	// ErrLengthMismatch indicates a TPDU length constraint was violated (e.g. CR exceeds 128 octets).
	ErrLengthMismatch = errors.New("cotp: length mismatch")
	// ErrUnknownTPDUType indicates the TPDU type code is not recognized.
	ErrUnknownTPDUType = errors.New("cotp: unknown TPDU type")
	// ErrInvalidTPDUCode indicates a reserved or invalid TPDU code.
	ErrInvalidTPDUCode = errors.New("cotp: invalid TPDU code")
	// ErrReservedTPDU indicates a reserved TPDU type code.
	ErrReservedTPDU = errors.New("cotp: reserved TPDU type")
	// ErrMalformedParameter indicates a parameter block is malformed (e.g. length overrun).
	ErrMalformedParameter = errors.New("cotp: malformed parameter")
	// ErrUnexpectedParameterLength indicates a parameter length is outside the allowed range.
	ErrUnexpectedParameterLength = errors.New("cotp: unexpected parameter length")
	// ErrUnsupportedTPDU indicates the TPDU type is structurally valid but not supported by this decoder (reserved or unknown type codes).
	ErrUnsupportedTPDU = errors.New("cotp: unsupported TPDU type")
	// ErrUnsupportedDTVariant indicates a valid X.224 DT shape (e.g. extended format) that this decoder does not support.
	ErrUnsupportedDTVariant = errors.New("cotp: unsupported DT variant")
	// ErrInvalidClassOption indicates an invalid class/option field.
	ErrInvalidClassOption = errors.New("cotp: invalid class option")
	// ErrDuplicateKnownParameter is retained for compatibility. Decode follows X.224 13.2.3
	// (last duplicate value wins) and no longer returns this error.
	ErrDuplicateKnownParameter = errors.New("cotp: duplicate known parameter")
	// ErrInvalidEDUserDataLength indicates ED user data length is not in 1–16 octets (X.224).
	ErrInvalidEDUserDataLength = errors.New("cotp: invalid ED user data length")
	// ErrNilReceiver indicates a method was called on a nil receiver (e.g. MarshalBinary on nil *CR).
	ErrNilReceiver = errors.New("cotp: nil receiver")
	// ErrMissingRequiredField indicates a required field for encode is missing or invalid.
	ErrMissingRequiredField = errors.New("cotp: missing required field")
	// ErrInvalidConfig indicates invalid TP0/ITOT service configuration or callback policy input.
	ErrInvalidConfig = errors.New("cotp: invalid configuration")
	// ErrHandshake indicates a TP0 handshake or open-state protocol validation failure.
	ErrHandshake = errors.New("cotp: handshake failed")
	// ErrEmptyTSDU indicates a zero-length TSDU was rejected (P1 local policy).
	ErrEmptyTSDU = errors.New("cotp: empty TSDU")
	// ErrTSDUTooLarge indicates a TSDU exceeds the configured MaxTSDULength.
	ErrTSDUTooLarge = errors.New("cotp: TSDU exceeds configured maximum")
	// ErrClosed indicates the local connection was closed (or aborted after I/O).
	ErrClosed = errors.New("cotp: connection closed")
	// ErrDisconnected indicates the peer disconnected (EOF/reset), not a local Close.
	ErrDisconnected = errors.New("cotp: peer disconnected")
	// ErrConnectionRefused indicates the peer refused the connection (DR during handshake).
	ErrConnectionRefused = errors.New("cotp: connection refused")
	// ErrUnexpectedTPDU indicates a TPDU that is not legal in the current phase.
	ErrUnexpectedTPDU = errors.New("cotp: unexpected TPDU")
	// ErrIncompleteTSDU indicates EOF or abort while reassembling a multi-DT TSDU.
	ErrIncompleteTSDU = errors.New("cotp: incomplete TSDU")
)
