// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// CC fixed part is 6 octets (octets 2–7): same as CR.
const ccFixedPartLength = 6

// DecodeCC decodes a Connection Confirm TPDU from b.
// Same semantics as DecodeCR for selectors and parameters; UserData after the header is exposed.
func DecodeCC(b []byte) (*CC, error) {
	if len(b) < 1+ccFixedPartLength {
		return nil, fmt.Errorf("decode CC: %w", ErrTooShort)
	}
	li, err := ReadLI(b)
	if err != nil {
		return nil, fmt.Errorf("decode CC: %w", err)
	}
	headerLen, err := headerBounds(b, li, ccFixedPartLength)
	if err != nil {
		return nil, fmt.Errorf("decode CC: %w", err)
	}
	if b[1]&0xF0 != 0xD0 {
		return nil, fmt.Errorf("decode CC: not a CC TPDU (code 0x%02x): %w", b[1], ErrInvalidTPDUCode)
	}
	cdt := b[1] & 0x0F
	dstRef := binary.BigEndian.Uint16(b[2:4])
	srcRef := binary.BigEndian.Uint16(b[4:6])
	classOption := b[6]

	cc := &CC{
		CDT:            cdt,
		DestinationRef: dstRef,
		SourceRef:      srcRef,
		ClassOption:    classOption,
	}

	if headerLen > 7 {
		variable := b[7:headerLen]
		res, err := parseCRCCVariablePart(variable)
		if err != nil {
			return nil, fmt.Errorf("decode CC: %w", err)
		}
		cc.CallingSelector = res.callingSelector
		cc.CalledSelector = res.calledSelector
		cc.TPDUSize = res.tpduSize
		cc.PreferredMaxTPDUSize = res.preferredMaxTPDUSize
		cc.Parameters = res.parameters
	}
	cc.UserData = b[headerLen:]

	return cc, nil
}
