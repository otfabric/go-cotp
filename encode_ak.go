// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the AK as a COTP TPDU (X.224 13.9).
func (a *AK) MarshalBinary() ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("marshal AK: %w", ErrNilReceiver)
	}
	var varPart []byte
	for _, p := range a.Parameters {
		if len(p.Value) > 255 {
			return nil, fmt.Errorf("marshal AK: parameter 0x%02x value length %d: %w", p.Code, len(p.Value), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, p.Code, byte(len(p.Value)))
		varPart = append(varPart, p.Value...)
	}
	li := 4 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal AK: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}
	out := make([]byte, 0, 1+li)
	out = append(out, byte(li))
	out = append(out, 0x60|(a.CDT&0x0F))
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], a.DestinationRef)
	out = append(out, ref[:]...)
	out = append(out, a.YRTUNR)
	out = append(out, varPart...)
	return out, nil
}
