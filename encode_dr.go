// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the DR as a COTP TPDU (X.224 13.5).
func (d *DR) MarshalBinary() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("marshal DR: %w", ErrNilReceiver)
	}
	var varPart []byte
	for _, p := range d.Parameters {
		if len(p.Value) > 255 {
			return nil, fmt.Errorf("marshal DR: parameter 0x%02x value length %d: %w", p.Code, len(p.Value), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, p.Code, byte(len(p.Value)))
		varPart = append(varPart, p.Value...)
	}
	li := 6 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal DR: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}
	userData := d.UserData
	if userData == nil {
		userData = []byte{}
	}
	out := make([]byte, 0, 1+li+len(userData))
	out = append(out, byte(li))
	out = append(out, 0x80)
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], d.DestinationRef)
	out = append(out, ref[:]...)
	binary.BigEndian.PutUint16(ref[:], d.SourceRef)
	out = append(out, ref[:]...)
	out = append(out, d.Reason)
	out = append(out, varPart...)
	out = append(out, userData...)
	return out, nil
}
