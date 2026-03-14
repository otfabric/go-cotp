package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the ED as a COTP TPDU (X.224 13.8).
// User data must be 1–16 octets.
func (e *ED) MarshalBinary() ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("marshal ED: %w", ErrNilReceiver)
	}
	if e.DestinationRef == nil || e.TPDUNR == nil {
		return nil, fmt.Errorf("marshal ED: DestinationRef and TPDUNR required: %w", ErrMissingRequiredField)
	}
	userData := e.UserData
	if userData == nil {
		userData = []byte{}
	}
	if len(userData) < MinEDUserDataLen || len(userData) > MaxEDUserDataLen {
		return nil, fmt.Errorf("marshal ED: user data length %d: %w", len(userData), ErrInvalidEDUserDataLength)
	}
	var varPart []byte
	for _, p := range e.Parameters {
		if len(p.Value) > 255 {
			return nil, fmt.Errorf("marshal ED: parameter 0x%02x value length %d: %w", p.Code, len(p.Value), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, p.Code, byte(len(p.Value)))
		varPart = append(varPart, p.Value...)
	}
	li := 4 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal ED: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}
	nrOctet := *e.TPDUNR & 0x7F
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
