// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// CR fixed part is 6 octets (octets 2–7): code+CDT, DST-REF, SRC-REF, ClassOption.
const crFixedPartLength = 6

// DecodeCR decodes a Connection Request TPDU from b.
// The buffer must be a complete COTP TPDU payload (e.g. from tpkt.DecodePacket).
// Returned CR's selector, Parameter.Value, and UserData slices may alias b.
// User data (octets after the header) is exposed. Total CR length must be ≤ MaxCRTPDULength (128).
func DecodeCR(b []byte) (*CR, error) {
	if len(b) < 1+crFixedPartLength {
		return nil, fmt.Errorf("decode CR: %w", ErrTooShort)
	}
	if len(b) > MaxCRTPDULength {
		return nil, fmt.Errorf("decode CR: length %d > %d: %w", len(b), MaxCRTPDULength, ErrLengthMismatch)
	}
	li, err := ReadLI(b)
	if err != nil {
		return nil, fmt.Errorf("decode CR: %w", err)
	}
	headerLen, err := headerBounds(b, li, crFixedPartLength)
	if err != nil {
		return nil, fmt.Errorf("decode CR: %w", err)
	}
	// Octet 2: code + CDT
	if b[1]&0xF0 != 0xE0 {
		return nil, fmt.Errorf("decode CR: not a CR TPDU (code 0x%02x): %w", b[1], ErrInvalidTPDUCode)
	}
	cdt := b[1] & 0x0F
	// Octets 3–4: DST-REF (big-endian)
	dstRef := binary.BigEndian.Uint16(b[2:4])
	// Octets 5–6: SRC-REF
	srcRef := binary.BigEndian.Uint16(b[4:6])
	// Octet 7: ClassOption
	classOption := b[6]

	cr := &CR{
		CDT:            cdt,
		DestinationRef: dstRef,
		SourceRef:      srcRef,
		ClassOption:    classOption,
	}

	// Variable part: octets 8 to headerLen (index 7 to headerLen-1)
	if headerLen > 7 {
		variable := b[7:headerLen]
		res, err := parseCRCCVariablePart(variable)
		if err != nil {
			return nil, fmt.Errorf("decode CR: %w", err)
		}
		cr.CallingSelector = res.callingSelector
		cr.CalledSelector = res.calledSelector
		cr.TPDUSize = res.tpduSize
		cr.Parameters = res.parameters
	}
	cr.UserData = b[headerLen:]

	return cr, nil
}
