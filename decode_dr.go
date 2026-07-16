// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// DR fixed part: 6 octets (code, DST-REF, SRC-REF, REASON). Header = LI (1) + this. X.224 13.5.
const drFixedPartLength = 6

// DecodeDR decodes a Disconnect Request TPDU from b.
// UserData (octets after header, ≤64 in spec) is exposed; may alias b.
func DecodeDR(b []byte) (*DR, error) {
	if len(b) < 1+drFixedPartLength {
		return nil, fmt.Errorf("decode DR: %w", ErrTooShort)
	}
	li, err := ReadLI(b)
	if err != nil {
		return nil, fmt.Errorf("decode DR: %w", err)
	}
	headerLen := 1 + int(li)
	if len(b) < headerLen {
		return nil, fmt.Errorf("decode DR: header length %d exceeds buffer %d: %w", headerLen, len(b), ErrTooShort)
	}
	if b[1] != 0x80 {
		return nil, fmt.Errorf("decode DR: not a DR TPDU (code 0x%02x): %w", b[1], ErrInvalidTPDUCode)
	}
	dr := &DR{
		DestinationRef: binary.BigEndian.Uint16(b[2:4]),
		SourceRef:      binary.BigEndian.Uint16(b[4:6]),
		Reason:         b[6],
	}
	if headerLen > 7 {
		params, err := parseVariablePart(b[7:headerLen])
		if err != nil {
			return nil, fmt.Errorf("decode DR: %w", err)
		}
		dr.Parameters = params
	}
	dr.UserData = b[headerLen:]
	return dr, nil
}
