// SPDX-License-Identifier: MIT

package cotp

import (
	"fmt"
)

// ConnectionPhase is a stable public phase for typed errors — not the full
// internal state-machine vocabulary.
type ConnectionPhase uint8

const (
	PhaseHandshake ConnectionPhase = iota
	PhaseDataTransfer
)

// RejectionError is returned when the peer refuses a connection with DR.
type RejectionError struct {
	Reason DisconnectReason
	Info   []byte
}

func (e *RejectionError) Error() string {
	if e == nil {
		return "cotp: connection refused"
	}
	return fmt.Sprintf("cotp: connection refused (reason %d)", e.Reason)
}

func (e *RejectionError) Unwrap() error { return ErrConnectionRefused }

// UnexpectedTPDUError is returned when a TPDU is illegal for the current phase.
type UnexpectedTPDUError struct {
	Type  TPDUType
	Phase ConnectionPhase
}

func (e *UnexpectedTPDUError) Error() string {
	if e == nil {
		return "cotp: unexpected TPDU"
	}
	phase := "handshake"
	if e.Phase == PhaseDataTransfer {
		phase = "data transfer"
	}
	return fmt.Sprintf("cotp: unexpected %s during %s", e.Type, phase)
}

func (e *UnexpectedTPDUError) Unwrap() error { return ErrUnexpectedTPDU }

// DisconnectError joins ErrDisconnected with an underlying cause (e.g. io.EOF).
type DisconnectError struct {
	Cause error
}

func (e *DisconnectError) Error() string {
	if e == nil || e.Cause == nil {
		return ErrDisconnected.Error()
	}
	return fmt.Sprintf("%v: %v", ErrDisconnected, e.Cause)
}

func (e *DisconnectError) Unwrap() []error {
	if e == nil {
		return []error{ErrDisconnected}
	}
	if e.Cause == nil {
		return []error{ErrDisconnected}
	}
	return []error{ErrDisconnected, e.Cause}
}
