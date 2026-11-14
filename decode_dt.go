// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// DT minimal: fixed part 2 octets (octet 2 = DT+ROA, octet 3 = TPDU-NR+EOT). LI=2.
const dtMinimalFixedLength = 2

// DT normal (class 2–4): fixed part 4 octets (DT+ROA, DST-REF, TPDU-NR+EOT). LI>=4 and even.
const dtNormalFixedLength = 4

// DecodeDT decodes a Data TPDU from b. v1 supports the class 0 and 1 format
// (LI=2) and the normal class 2 to 4 format (an even LI of 4 or more).
//
// The extended class 2 to 4 format has a 7-octet fixed part, so its LI is odd:
// X.224 §13.7.4 NOTE states the rule that an even LI is the normal format and
// an odd LI the extended one. DecodeDT follows it: an odd LI of 5 or more is
// rejected with ErrUnsupportedDTVariant, as are LI 0, 1 and 3.
//
// Returned UserData and Parameter values alias b and have no capacity beyond
// their own octets; see package doc.
func DecodeDT(b []byte) (*DT, error) {
	if len(b) < MinHeaderLength {
		return nil, fmt.Errorf("decode DT: %w", ErrTooShort)
	}
	li, err := ReadLI(b)
	if err != nil {
		return nil, fmt.Errorf("decode DT: %w", err)
	}
	headerLen := 1 + int(li)
	if len(b) < headerLen {
		return nil, fmt.Errorf("decode DT: header length %d exceeds buffer %d: %w", headerLen, len(b), ErrTooShort)
	}
	// Match PeekType / LooksLikeDT: 1111 000y (ROA in low bit only).
	if b[1]&0xFE != 0xF0 {
		return nil, fmt.Errorf("decode DT: not a DT TPDU (code 0x%02x): %w", b[1], ErrInvalidTPDUCode)
	}

	dt := &DT{}

	switch {
	case li == 2:
		// Minimal (class 0/1): fixed part b[1], b[2]
		if headerLen < 1+dtMinimalFixedLength {
			return nil, fmt.Errorf("decode DT: %w", ErrUnsupportedDTVariant)
		}
		// Octet 3: TPDU-NR (bits 1–7), EOT (bit 8)
		nr := b[2] & 0x7F
		dt.TPDUNR = &nr
		dt.EOT = (b[2] & 0x80) != 0
		dt.DestinationRef = nil
		if headerLen > 3 {
			varPart := b[3:headerLen]
			params, err := parseVariablePart(varPart)
			if err != nil {
				return nil, fmt.Errorf("decode DT: %w", err)
			}
			dt.Parameters = params
		}
		dt.UserData = b[headerLen:len(b):len(b)]
	case li >= 4 && li%2 == 0:
		// Normal (class 2–4): fixed part b[1..4]. An odd LI is the extended
		// format (X.224 §13.7.4 NOTE) and falls through to the default case.
		if headerLen < 1+dtNormalFixedLength {
			return nil, fmt.Errorf("decode DT: %w", ErrUnsupportedDTVariant)
		}
		// DST-REF at b[2:4], TPDU-NR+EOT in b[4]
		dstRef := binary.BigEndian.Uint16(b[2:4])
		dt.DestinationRef = &dstRef
		nr := b[4] & 0x7F
		dt.TPDUNR = &nr
		dt.EOT = (b[4] & 0x80) != 0
		if headerLen > 5 {
			varPart := b[5:headerLen]
			params, err := parseVariablePart(varPart)
			if err != nil {
				return nil, fmt.Errorf("decode DT: %w", err)
			}
			dt.Parameters = params
		}
		dt.UserData = b[headerLen:len(b):len(b)]
	default:
		return nil, fmt.Errorf("decode DT: LI=%d: %w", li, ErrUnsupportedDTVariant)
	}

	return dt, nil
}
