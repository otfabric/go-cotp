package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the CR as a COTP TPDU (X.224 13.3).
// Known parameters are emitted in canonical order (0xC1, 0xC2, 0xC0); then unknown Parameters.
// No user data in v1. Deterministic: same CR produces same bytes.
func (c *CR) MarshalBinary() ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("marshal CR: %w", ErrNilReceiver)
	}
	// Build variable part: canonical order for known, then unknown
	var varPart []byte
	// 0xC1 CallingSelector
	if c.CallingSelector != nil {
		varPart = append(varPart, ParamCallingSelector, byte(len(c.CallingSelector)))
		varPart = append(varPart, c.CallingSelector...)
	}
	// 0xC2 CalledSelector
	if c.CalledSelector != nil {
		varPart = append(varPart, ParamCalledSelector, byte(len(c.CalledSelector)))
		varPart = append(varPart, c.CalledSelector...)
	}
	// 0xC0 TPDU size
	if c.TPDUSize != nil {
		varPart = append(varPart, ParamTPDUSize, 1, *c.TPDUSize)
	}
	// Unknown parameters (ignore known codes if they appear in Parameters)
	for _, p := range c.Parameters {
		if p.Code == ParamCallingSelector || p.Code == ParamCalledSelector || p.Code == ParamTPDUSize {
			continue
		}
		if len(p.Value) > 255 {
			return nil, fmt.Errorf("marshal CR: parameter 0x%02x value length %d: %w", p.Code, len(p.Value), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, p.Code, byte(len(p.Value)))
		varPart = append(varPart, p.Value...)
	}

	// LI = header length excluding LI byte = 6 (fixed) + len(varPart)
	li := 6 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal CR: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}

	out := make([]byte, 0, 1+6+len(varPart))
	out = append(out, byte(li))
	out = append(out, 0xE0|(c.CDT&0x0F)) // CR code + CDT
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], c.DestinationRef)
	out = append(out, ref[:]...)
	binary.BigEndian.PutUint16(ref[:], c.SourceRef)
	out = append(out, ref[:]...)
	out = append(out, c.ClassOption)
	out = append(out, varPart...)
	return out, nil
}
