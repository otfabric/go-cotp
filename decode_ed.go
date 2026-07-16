// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// ED fixed part: 4 octets (code, DST-REF, ED-TPDU-NR+EOT). Header = LI (1) + this. X.224 13.8.
const edFixedPartLength = 4

// MinEDUserDataLen and MaxEDUserDataLen are the X.224 limits for ED user data.
const MinEDUserDataLen = 1
const MaxEDUserDataLen = 16

// DecodeED decodes an Expedited Data TPDU from b.
// User data must be 1–16 octets; UserData may alias b.
func DecodeED(b []byte) (*ED, error) {
	if len(b) < 1+edFixedPartLength {
		return nil, fmt.Errorf("decode ED: %w", ErrTooShort)
	}
	li, err := ReadLI(b)
	if err != nil {
		return nil, fmt.Errorf("decode ED: %w", err)
	}
	headerLen := 1 + int(li)
	if len(b) < headerLen {
		return nil, fmt.Errorf("decode ED: header length %d exceeds buffer %d: %w", headerLen, len(b), ErrTooShort)
	}
	if b[1] != 0x10 {
		return nil, fmt.Errorf("decode ED: not an ED TPDU (code 0x%02x): %w", b[1], ErrInvalidTPDUCode)
	}
	dstRef := binary.BigEndian.Uint16(b[2:4])
	nrEot := b[4]
	nr := nrEot & 0x7F
	eot := (nrEot & 0x80) != 0

	ed := &ED{
		DestinationRef: &dstRef,
		TPDUNR:         &nr,
		EOT:            eot,
	}
	if headerLen > 5 {
		params, err := parseVariablePart(b[5:headerLen])
		if err != nil {
			return nil, fmt.Errorf("decode ED: %w", err)
		}
		ed.Parameters = params
	}
	ed.UserData = b[headerLen:]
	if len(ed.UserData) < MinEDUserDataLen || len(ed.UserData) > MaxEDUserDataLen {
		return nil, fmt.Errorf("decode ED: user data length %d: %w", len(ed.UserData), ErrInvalidEDUserDataLength)
	}
	return ed, nil
}
