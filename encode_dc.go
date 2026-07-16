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
	var varPart []byte
	for _, p := range d.Parameters {
		if len(p.Value) > 255 {
			return nil, fmt.Errorf("marshal DC: parameter 0x%02x value length %d: %w", p.Code, len(p.Value), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, p.Code, byte(len(p.Value)))
		varPart = append(varPart, p.Value...)
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
