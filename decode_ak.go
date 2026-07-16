// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// AK fixed part: 4 octets (code+CDT, DST-REF, YR-TU-NR). Header = LI (1) + this. X.224 13.9.
const akFixedPartLength = 4

// DecodeAK decodes an Acknowledge TPDU from b.
// Type check: octet2&0xF0==0x60; CDT = octet2&0x0F.
func DecodeAK(b []byte) (*AK, error) {
	if len(b) < 1+akFixedPartLength {
		return nil, fmt.Errorf("decode AK: %w", ErrTooShort)
	}
	li, err := ReadLI(b)
	if err != nil {
		return nil, fmt.Errorf("decode AK: %w", err)
	}
	headerLen := 1 + int(li)
	if len(b) < headerLen {
		return nil, fmt.Errorf("decode AK: header length %d exceeds buffer %d: %w", headerLen, len(b), ErrTooShort)
	}
	if b[1]&0xF0 != 0x60 {
		return nil, fmt.Errorf("decode AK: not an AK TPDU (code 0x%02x): %w", b[1], ErrInvalidTPDUCode)
	}
	ak := &AK{
		CDT:            b[1] & 0x0F,
		DestinationRef: binary.BigEndian.Uint16(b[2:4]),
		YRTUNR:         b[4],
	}
	if headerLen > 5 {
		params, err := parseVariablePart(b[5:headerLen])
		if err != nil {
			return nil, fmt.Errorf("decode AK: %w", err)
		}
		ak.Parameters = params
	}
	return ak, nil
}
