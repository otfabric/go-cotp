// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// DC fixed part: 5 octets (code, DST-REF, SRC-REF). Header = LI (1) + this. X.224 13.6.
const dcFixedPartLength = 5

// DecodeDC decodes a Disconnect Confirm TPDU from b.
func DecodeDC(b []byte) (*DC, error) {
	if len(b) < 1+dcFixedPartLength {
		return nil, fmt.Errorf("decode DC: %w", ErrTooShort)
	}
	li, err := ReadLI(b)
	if err != nil {
		return nil, fmt.Errorf("decode DC: %w", err)
	}
	headerLen, err := headerBounds(b, li, dcFixedPartLength)
	if err != nil {
		return nil, fmt.Errorf("decode DC: %w", err)
	}
	if b[1] != 0xC0 {
		return nil, fmt.Errorf("decode DC: not a DC TPDU (code 0x%02x): %w", b[1], ErrInvalidTPDUCode)
	}
	dc := &DC{
		DestinationRef: binary.BigEndian.Uint16(b[2:4]),
		SourceRef:      binary.BigEndian.Uint16(b[4:6]),
	}
	if headerLen > 6 {
		params, err := parseVariablePart(b[6:headerLen])
		if err != nil {
			return nil, fmt.Errorf("decode DC: %w", err)
		}
		dc.Parameters = params
	}
	return dc, nil
}
