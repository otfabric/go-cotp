// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the DC as a COTP TPDU (X.224 13.6).
func (d *DC) MarshalBinary() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("marshal DC: %w", ErrNilReceiver)
	}
	varPart, err := encodeVariablePart(d.Parameters)
	if err != nil {
		return nil, fmt.Errorf("marshal DC: %w", err)
	}
	li := 5 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal DC: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}
	out := make([]byte, 0, 1+li)
	out = append(out, byte(li))
	out = append(out, 0xC0)
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], d.DestinationRef)
	out = append(out, ref[:]...)
	binary.BigEndian.PutUint16(ref[:], d.SourceRef)
	out = append(out, ref[:]...)
	out = append(out, varPart...)
	return out, nil
}
