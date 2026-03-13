package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the ER as a COTP TPDU (X.224 13.12).
func (e *ER) MarshalBinary() ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("marshal ER: %w", ErrNilReceiver)
	}
	var varPart []byte
	for _, p := range e.Parameters {
		if len(p.Value) > 255 {
			return nil, fmt.Errorf("marshal ER: parameter 0x%02x value length %d: %w", p.Code, len(p.Value), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, p.Code, byte(len(p.Value)))
		varPart = append(varPart, p.Value...)
	}
	li := 4 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal ER: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}
	out := make([]byte, 0, 1+li)
	out = append(out, byte(li))
	out = append(out, 0x70)
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], e.DestinationRef)
	out = append(out, ref[:]...)
	out = append(out, e.RejectCause)
	out = append(out, varPart...)
	return out, nil
}
