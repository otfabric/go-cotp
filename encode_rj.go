// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the RJ as a COTP TPDU (X.224 13.11). No variable part.
func (r *RJ) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("marshal RJ: %w", ErrNilReceiver)
	}
	out := make([]byte, 0, 1+rjFixedPartLength)
	out = append(out, 4) // LI = 4 (fixed part only)
	out = append(out, 0x50|(r.CDT&0x0F))
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], r.DestinationRef)
	out = append(out, ref[:]...)
	out = append(out, r.YRTUNR)
	return out, nil
}
