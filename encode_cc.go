package cotp

import (
	"encoding/binary"
	"fmt"
)

// MarshalBinary encodes the CC as a COTP TPDU (X.224 13.4).
// Same rules as CR: canonical order 0xC1, 0xC2, 0xC0; then unknown Parameters; no user data in v1.
func (c *CC) MarshalBinary() ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("marshal CC: %w", ErrNilReceiver)
	}
	var varPart []byte
	if c.CallingSelector != nil {
		varPart = append(varPart, ParamCallingSelector, byte(len(c.CallingSelector)))
		varPart = append(varPart, c.CallingSelector...)
	}
	if c.CalledSelector != nil {
		varPart = append(varPart, ParamCalledSelector, byte(len(c.CalledSelector)))
		varPart = append(varPart, c.CalledSelector...)
	}
	if c.TPDUSize != nil {
		varPart = append(varPart, ParamTPDUSize, 1, *c.TPDUSize)
	}
	for _, p := range c.Parameters {
		if p.Code == ParamCallingSelector || p.Code == ParamCalledSelector || p.Code == ParamTPDUSize {
			continue
		}
		if len(p.Value) > 255 {
			return nil, fmt.Errorf("marshal CC: parameter 0x%02x value length %d: %w", p.Code, len(p.Value), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, p.Code, byte(len(p.Value)))
		varPart = append(varPart, p.Value...)
	}

	li := 6 + len(varPart)
	if li > MaxLI {
		return nil, fmt.Errorf("marshal CC: header length %d > %d: %w", li, MaxLI, ErrInvalidLI)
	}

	out := make([]byte, 0, 1+6+len(varPart))
	out = append(out, byte(li))
	out = append(out, 0xD0|(c.CDT&0x0F))
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], c.DestinationRef)
	out = append(out, ref[:]...)
	binary.BigEndian.PutUint16(ref[:], c.SourceRef)
	out = append(out, ref[:]...)
	out = append(out, c.ClassOption)
	out = append(out, varPart...)
	return out, nil
}
