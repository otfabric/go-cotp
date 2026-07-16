// SPDX-License-Identifier: MIT

package cotp

import "fmt"

// crccVariableResult holds the result of parsing CR/CC variable part.
// DecodeCR/DecodeCC map this into CR/CC structs; the parser does not mutate TPDU structs.
type crccVariableResult struct {
	callingSelector      []byte
	calledSelector       []byte
	tpduSize             *uint8
	preferredMaxTPDUSize *uint32
	parameters           []Parameter
}

// parseCRCCVariablePart parses the variable part (octets 8..p) of a CR or CC TPDU.
// Each parameter is code (1), length (1), value (length octets).
// Duplicate known parameters (0xC1, 0xC2, 0xC0, 0xF0) follow X.224 13.2.3: the last value wins.
// Unknown parameters are appended to the result (all occurrences preserved in order).
// Value slices may alias b.
func parseCRCCVariablePart(b []byte) (*crccVariableResult, error) {
	r := &crccVariableResult{}
	pos := 0
	for pos < len(b) {
		if pos+2 > len(b) {
			return nil, fmt.Errorf("variable part: %w", ErrMalformedParameter)
		}
		code := b[pos]
		length := int(b[pos+1])
		pos += 2
		if pos+length > len(b) {
			return nil, fmt.Errorf("variable part: length overrun: %w", ErrMalformedParameter)
		}
		value := b[pos : pos+length]
		pos += length

		switch code {
		case ParamCallingSelector:
			r.callingSelector = value
		case ParamCalledSelector:
			r.calledSelector = value
		case ParamTPDUSize:
			if length != 1 {
				return nil, fmt.Errorf("variable part: TPDU size length %d: %w", length, ErrUnexpectedParameterLength)
			}
			v := value[0]
			r.tpduSize = &v
		case ParamPreferredMaxTPDUSize:
			units, err := decodePreferredMaxUnits(value)
			if err != nil {
				return nil, fmt.Errorf("variable part: %w", err)
			}
			u := units
			r.preferredMaxTPDUSize = &u
		default:
			r.parameters = append(r.parameters, Parameter{Code: code, Value: value})
		}
	}
	return r, nil
}

// parseVariablePart parses a generic variable part (code+length+value) into a slice of Parameters.
// Used by DT, DR, DC, ER. Value slices may alias b.
func parseVariablePart(b []byte) ([]Parameter, error) {
	var params []Parameter
	pos := 0
	for pos < len(b) {
		if pos+2 > len(b) {
			return nil, fmt.Errorf("variable part: %w", ErrMalformedParameter)
		}
		code := b[pos]
		length := int(b[pos+1])
		pos += 2
		if pos+length > len(b) {
			return nil, fmt.Errorf("variable part: length overrun: %w", ErrMalformedParameter)
		}
		params = append(params, Parameter{Code: code, Value: b[pos : pos+length]})
		pos += length
	}
	return params, nil
}

// encodeCRCCVariablePart builds the CR/CC variable part in canonical order
// (0xC1, 0xC2, 0xC0, 0xF0) then unknown Parameters. This order is a local
// deterministic encoding policy, not an X.224 requirement.
// Selector and unknown values longer than MaxParameterValueLength are rejected.
func encodeCRCCVariablePart(calling, called []byte, tpduSize *uint8, preferredMax *uint32, params []Parameter, what string) ([]byte, error) {
	var varPart []byte
	if calling != nil {
		if len(calling) > MaxParameterValueLength {
			return nil, fmt.Errorf("marshal %s: calling selector length %d: %w", what, len(calling), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, ParamCallingSelector, byte(len(calling)))
		varPart = append(varPart, calling...)
	}
	if called != nil {
		if len(called) > MaxParameterValueLength {
			return nil, fmt.Errorf("marshal %s: called selector length %d: %w", what, len(called), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, ParamCalledSelector, byte(len(called)))
		varPart = append(varPart, called...)
	}
	if tpduSize != nil {
		varPart = append(varPart, ParamTPDUSize, 1, *tpduSize)
	}
	if preferredMax != nil {
		enc, err := encodePreferredMaxUnits(*preferredMax)
		if err != nil {
			return nil, fmt.Errorf("marshal %s: %w", what, err)
		}
		varPart = append(varPart, ParamPreferredMaxTPDUSize, byte(len(enc)))
		varPart = append(varPart, enc...)
	}
	for _, p := range params {
		if p.Code == ParamCallingSelector || p.Code == ParamCalledSelector ||
			p.Code == ParamTPDUSize || p.Code == ParamPreferredMaxTPDUSize {
			continue
		}
		if len(p.Value) > MaxParameterValueLength {
			return nil, fmt.Errorf("marshal %s: parameter 0x%02x value length %d: %w", what, p.Code, len(p.Value), ErrUnexpectedParameterLength)
		}
		varPart = append(varPart, p.Code, byte(len(p.Value)))
		varPart = append(varPart, p.Value...)
	}
	return varPart, nil
}
