// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the DT as a COTP TPDU (X.224 13.7).
// Minimal format (no DestinationRef, no variable part): LI=2, 2-octet fixed part.
// Normal format: LI=4+len(variable), 4-octet fixed part, then variable, then user data.
// UserData nil or zero-length is valid (empty payload). Deterministic for same DT.
func (d *DT) MarshalBinary() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("marshal DT: %w", ErrNilReceiver)
	}

	var fixedPart []byte
	var li int

	if d.DestinationRef == nil {
		// Minimal: LI=2, fixed = DT+ROA (0xF0), TPDU-NR+EOT in second octet
		nr := byte(0)
		if d.TPDUNR != nil {
			nr = *d.TPDUNR & 0x7F
		}
		if d.EOT {
			nr |= 0x80
		}
		fixedPart = []byte{0xF0, nr}
		li = 2
	} else {
		// Normal: 4-octet fixed
		nr := byte(0)
		if d.TPDUNR != nil {
			nr = *d.TPDUNR & 0x7F
		}
		if d.EOT {
			nr |= 0x80
		}
		ref := make([]byte, 2)
		binary.BigEndian.PutUint16(ref, *d.DestinationRef)
		fixedPart = []byte{0xF0, ref[0], ref[1], nr}
		li = 4
	}

	// Variable part from Parameters
	var varPart []byte
	for _, p := range d.Parameters {
		if len(p.Value) > 255 {
			return nil, fmt.Errorf("marshal DT: parameter 0x%02x value length %d: %w", p.Code, len(p.Value), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, p.Code, byte(len(p.Value)))
		varPart = append(varPart, p.Value...)
	}

	li += len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal DT: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}

	userData := d.UserData
	if userData == nil {
		userData = []byte{}
	}

	out := make([]byte, 0, 1+li+len(userData))
	out = append(out, byte(li))
	out = append(out, fixedPart...)
	out = append(out, varPart...)
	out = append(out, userData...)
	return out, nil
}
