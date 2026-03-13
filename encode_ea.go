package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the EA as a COTP TPDU (X.224 13.10).
func (e *EA) MarshalBinary() ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("marshal EA: %w", ErrNilReceiver)
	}
	var varPart []byte
	for _, p := range e.Parameters {
		if len(p.Value) > 255 {
			return nil, fmt.Errorf("marshal EA: parameter 0x%02x value length %d: %w", p.Code, len(p.Value), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, p.Code, byte(len(p.Value)))
		varPart = append(varPart, p.Value...)
	}
	li := 4 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal EA: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}
	out := make([]byte, 0, 1+li)
	out = append(out, byte(li))
	out = append(out, 0x20)
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], e.DestinationRef)
	out = append(out, ref[:]...)
	out = append(out, e.YREDTUNR)
	out = append(out, varPart...)
	return out, nil
}
