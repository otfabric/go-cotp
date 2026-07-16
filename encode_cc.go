// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the CC as a COTP TPDU (X.224 13.4).
// Same rules as CR: canonical order 0xC1, 0xC2, 0xC0; then unknown Parameters; then UserData.
func (c *CC) MarshalBinary() ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("marshal CC: %w", ErrNilReceiver)
	}
	varPart, err := encodeCRCCVariablePart(c.CallingSelector, c.CalledSelector, c.TPDUSize, c.Parameters, "CC")
	if err != nil {
		return nil, err
	}

	li := 6 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal CC: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}

	out := make([]byte, 0, 1+6+len(varPart)+len(c.UserData))
	out = append(out, byte(li))
	out = append(out, 0xD0|(c.CDT&0x0F))
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
