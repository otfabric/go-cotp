// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the RJ as a COTP TPDU (X.224 13.11), normal format. No variable part.
// A CDT above 15 does not fit its 4 bits and is refused with ErrMissingRequiredField.
func (r *RJ) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("marshal RJ: %w", ErrNilReceiver)
	}
	if err := checkCDT(r.CDT); err != nil {
		return nil, fmt.Errorf("marshal RJ: %w", err)
	}
	out := make([]byte, 0, 1+rjFixedPartLength)
	out = append(out, 4) // LI = 4 (fixed part only)
	out = append(out, 0x50|r.CDT)
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], r.DestinationRef)
	out = append(out, ref[:]...)
	out = append(out, r.YRTUNR)
	return out, nil
}
