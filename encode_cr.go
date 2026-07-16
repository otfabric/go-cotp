// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the CR as a COTP TPDU (X.224 13.3).
// Known parameters are emitted in canonical order (0xC1, 0xC2, 0xC0, 0xF0); then unknown Parameters;
// then UserData. Deterministic: same CR produces same bytes. Total length must be ≤ MaxCRTPDULength.
func (c *CR) MarshalBinary() ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("marshal CR: %w", ErrNilReceiver)
	}
	varPart, err := encodeCRCCVariablePart(c.CallingSelector, c.CalledSelector, c.TPDUSize, c.PreferredMaxTPDUSize, c.Parameters, "CR")
	if err != nil {
		return nil, err
	}

	// LI = header length excluding LI byte = 6 (fixed) + len(varPart)
	li := 6 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal CR: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}
	total := 1 + li + len(c.UserData)
	if total > MaxCRTPDULength {
		return nil, fmt.Errorf("marshal CR: length %d > %d: %w", total, MaxCRTPDULength, ErrLengthMismatch)
	}

	out := make([]byte, 0, total)
	out = append(out, byte(li))
	out = append(out, 0xE0|(c.CDT&0x0F)) // CR code + CDT
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], c.DestinationRef)
	out = append(out, ref[:]...)
	binary.BigEndian.PutUint16(ref[:], c.SourceRef)
	out = append(out, ref[:]...)
	out = append(out, c.ClassOption)
	out = append(out, varPart...)
	out = append(out, c.UserData...)
	return out, nil
}
