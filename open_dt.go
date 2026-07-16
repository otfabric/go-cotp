// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"fmt"
)

// decodeOpenDT validates one inbound TPKT payload as an open-state Class 0 DT.
// It does not mutate connection state; callers abort with abortOpen.
func decodeOpenDT(packet []byte, maxTPDU int) (*DT, error) {
	if len(packet) > maxTPDU {
		return nil, fmt.Errorf("TPDU length %d > negotiated %d: %w", len(packet), maxTPDU, ErrHandshake)
	}
	if len(packet) < MinHeaderLength {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, ErrTooShort)
	}

	decoded, err := Decode(packet)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	if decoded.Type != TypeDT || decoded.DT == nil {
		return nil, unexpectedOpenTPDU(decoded.Type)
	}

	li, err := ReadLI(packet)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	typeOctet := packet[1]
	tpduNRAndEOT := byte(0)
	if len(packet) > 2 {
		tpduNRAndEOT = packet[2]
	}
	if err := validateMinimalClass0DT(int(li), typeOctet, tpduNRAndEOT); err != nil {
		return nil, err
	}
	if decoded.DT.DestinationRef != nil {
		return nil, fmt.Errorf("non-minimal DT: %w", ErrHandshake)
	}
	if err := validateOpenDTParameters(decoded.DT.Parameters); err != nil {
		return nil, err
	}
	return decoded.DT, nil
}

func unexpectedOpenTPDU(t TPDUType) error {
	u := &UnexpectedTPDUError{Type: t, Phase: PhaseDataTransfer}
	if t == TypeDR {
		// Open-state DR is illegal for TP0-over-TCP and terminates the connection.
		return errors.Join(u, &DisconnectError{})
	}
	return u
}

// validateOpenDTParameters rejects any DT variable-part parameters in open-state TP0.
func validateOpenDTParameters(params []Parameter) error {
	if len(params) == 0 {
		return nil
	}
	p := params[0]
	if isKnownClass0ForbiddenParam(p.Code) {
		return fmt.Errorf("DT forbidden parameter 0x%02x: %w", p.Code, ErrHandshake)
	}
	return fmt.Errorf("DT unknown parameter 0x%02x: %w", p.Code, ErrHandshake)
}

// abortOpen records a terminal open-state protocol failure.
// When midTSDU is set, ErrIncompleteTSDU is joined unless already present.
func (c *Conn) abortOpen(midTSDU bool, err error) error {
	if err == nil {
		err = ErrHandshake
	}
	if midTSDU && !errors.Is(err, ErrIncompleteTSDU) {
		err = errors.Join(ErrIncompleteTSDU, err)
	}
	return c.abort(err)
}
