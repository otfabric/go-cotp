// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// EA fixed part: 4 octets (code, DST-REF, YR-EDTU-NR). Header = LI (1) + this. X.224 13.10.
const eaFixedPartLength = 4

// DecodeEA decodes an Expedited Acknowledge TPDU from b.
func DecodeEA(b []byte) (*EA, error) {
	if len(b) < 1+eaFixedPartLength {
		return nil, fmt.Errorf("decode EA: %w", ErrTooShort)
	}
	li, err := ReadLI(b)
	if err != nil {
		return nil, fmt.Errorf("decode EA: %w", err)
	}
	headerLen := 1 + int(li)
	if len(b) < headerLen {
		return nil, fmt.Errorf("decode EA: header length %d exceeds buffer %d: %w", headerLen, len(b), ErrTooShort)
	}
	if b[1] != 0x20 {
		return nil, fmt.Errorf("decode EA: not an EA TPDU (code 0x%02x): %w", b[1], ErrInvalidTPDUCode)
	}
	ea := &EA{
		DestinationRef: binary.BigEndian.Uint16(b[2:4]),
		YREDTUNR:       b[4],
	}
	if headerLen > 5 {
		params, err := parseVariablePart(b[5:headerLen])
		if err != nil {
			return nil, fmt.Errorf("decode EA: %w", err)
		}
		ea.Parameters = params
	}
	return ea, nil
}
