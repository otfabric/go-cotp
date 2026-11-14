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
//
// MarshalBinary writes only the formats DecodeDT reads back as they were
// built, and refuses the others:
//   - a TPDUNR above 127 does not fit its 7 bits: ErrMissingRequiredField;
//   - Parameters without a DestinationRef: X.224 13.7.1 a) gives the class 0
//     and 1 format no variable part (ErrUnsupportedDTVariant);
//   - a variable part of odd length, which makes LI odd: an odd LI is the
//     extended format (X.224 13.7.4 NOTE), ErrUnsupportedDTVariant.
func (d *DT) MarshalBinary() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("marshal DT: %w", ErrNilReceiver)
	}
	nr := byte(0)
	if d.TPDUNR != nil {
		if err := checkTPDUNR(*d.TPDUNR); err != nil {
			return nil, fmt.Errorf("marshal DT: %w", err)
		}
		nr = *d.TPDUNR
	}
	if d.EOT {
		nr |= 0x80
	}

	var fixedPart []byte
	var li int

	if d.DestinationRef == nil {
		if len(d.Parameters) > 0 {
			return nil, fmt.Errorf("marshal DT: %d parameters without DestinationRef: the class 0 and 1 format has no variable part: %w",
				len(d.Parameters), ErrUnsupportedDTVariant)
		}
		// Minimal: LI=2, fixed = DT+ROA (0xF0), TPDU-NR+EOT in second octet
		fixedPart = []byte{0xF0, nr}
		li = 2
	} else {
		// Normal: 4-octet fixed
		ref := make([]byte, 2)
		binary.BigEndian.PutUint16(ref, *d.DestinationRef)
		fixedPart = []byte{0xF0, ref[0], ref[1], nr}
		li = 4
	}

	// Variable part from Parameters
	varPart, err := encodeVariablePart(d.Parameters)
	if err != nil {
		return nil, fmt.Errorf("marshal DT: %w", err)
	}

	li += len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal DT: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}
	if li%2 != 0 {
		return nil, fmt.Errorf("marshal DT: variable part of %d octets makes LI %d odd, the extended format: %w",
			len(varPart), li, ErrUnsupportedDTVariant)
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
