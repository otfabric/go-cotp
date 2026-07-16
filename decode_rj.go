// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// RJ fixed part: 4 octets (code+CDT, DST-REF, YR-TU-NR). Header = LI (1) + this. No variable part. X.224 13.11.
const rjFixedPartLength = 4

// DecodeRJ decodes a Reject TPDU from b.
// RJ has no variable part; reject any LI > 4 (trailing bytes).
func DecodeRJ(b []byte) (*RJ, error) {
	if len(b) < 1+rjFixedPartLength {
		return nil, fmt.Errorf("decode RJ: %w", ErrTooShort)
	}
	li, err := ReadLI(b)
	if err != nil {
		return nil, fmt.Errorf("decode RJ: %w", err)
	}
	if li > 4 {
		return nil, fmt.Errorf("decode RJ: LI=%d (RJ has no variable part): %w", li, ErrMalformedParameter)
	}
	headerLen := 1 + int(li)
	if len(b) < headerLen {
		return nil, fmt.Errorf("decode RJ: header length %d exceeds buffer %d: %w", headerLen, len(b), ErrTooShort)
	}
	if b[1]&0xF0 != 0x50 {
		return nil, fmt.Errorf("decode RJ: not an RJ TPDU (code 0x%02x): %w", b[1], ErrInvalidTPDUCode)
	}
	rj := &RJ{
		CDT:            b[1] & 0x0F,
		DestinationRef: binary.BigEndian.Uint16(b[2:4]),
		YRTUNR:         b[4],
	}
	return rj, nil
}
