// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the ED as a COTP TPDU (X.224 13.8), normal format.
// User data must be 1–16 octets. A TPDUNR above 127 does not fit its 7 bits
// and is refused with ErrMissingRequiredField.
func (e *ED) MarshalBinary() ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("marshal ED: %w", ErrNilReceiver)
	}
	if e.DestinationRef == nil || e.TPDUNR == nil {
		return nil, fmt.Errorf("marshal ED: DestinationRef and TPDUNR required: %w", ErrMissingRequiredField)
	}
	if err := checkTPDUNR(*e.TPDUNR); err != nil {
		return nil, fmt.Errorf("marshal ED: %w", err)
	}
	userData := e.UserData
	if userData == nil {
		userData = []byte{}
	}
	if len(userData) < MinEDUserDataLen || len(userData) > MaxEDUserDataLen {
		return nil, fmt.Errorf("marshal ED: user data length %d: %w", len(userData), ErrInvalidEDUserDataLength)
	}
	varPart, err := encodeVariablePart(e.Parameters)
	if err != nil {
		return nil, fmt.Errorf("marshal ED: %w", err)
	}
	li := 4 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal ED: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}
	nrOctet := *e.TPDUNR
	if e.EOT {
		nrOctet |= 0x80
	}
	out := make([]byte, 0, 1+li+len(userData))
	out = append(out, byte(li))
	out = append(out, 0x10)
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], *e.DestinationRef)
	out = append(out, ref[:]...)
	out = append(out, nrOctet)
	out = append(out, varPart...)
	out = append(out, userData...)
	return out, nil
}
