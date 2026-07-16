// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// ER fixed part: 4 octets (code, DST-REF, REJECT CAUSE). Header = LI (1) + this. X.224 13.12.
const erFixedPartLength = 4

// DecodeER decodes a TPDU Error from b.
func DecodeER(b []byte) (*ER, error) {
	if len(b) < 1+erFixedPartLength {
		return nil, fmt.Errorf("decode ER: %w", ErrTooShort)
	}
	li, err := ReadLI(b)
	if err != nil {
		return nil, fmt.Errorf("decode ER: %w", err)
	}
	headerLen, err := headerBounds(b, li, erFixedPartLength)
	if err != nil {
		return nil, fmt.Errorf("decode ER: %w", err)
	}
	if b[1] != 0x70 {
		return nil, fmt.Errorf("decode ER: not an ER TPDU (code 0x%02x): %w", b[1], ErrInvalidTPDUCode)
	}
	er := &ER{
		DestinationRef: binary.BigEndian.Uint16(b[2:4]),
		RejectCause:    b[4],
	}
	if headerLen > 5 {
		params, err := parseVariablePart(b[5:headerLen])
		if err != nil {
			return nil, fmt.Errorf("decode ER: %w", err)
		}
		er.Parameters = params
	}
	return er, nil
}
