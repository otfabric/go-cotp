// SPDX-License-Identifier: MIT

package cotp

import "fmt"

// crccVariableResult holds the result of parsing CR/CC variable part.
// DecodeCR/DecodeCC map this into CR/CC structs; the parser does not mutate TPDU structs.
type crccVariableResult struct {
	callingSelector []byte
	calledSelector  []byte
	tpduSize        *uint8
	parameters      []Parameter
}

// parseCRCCVariablePart parses the variable part (octets 8..p) of a CR or CC TPDU.
// Each parameter is code (1), length (1), value (length octets).
// Duplicate known parameter (0xC1, 0xC2, 0xC0) returns ErrDuplicateKnownParameter.
// Unknown parameters are appended to the result. Value slices may alias b.
func parseCRCCVariablePart(b []byte) (*crccVariableResult, error) {
	r := &crccVariableResult{}
	seenKnown := make(map[uint8]bool)
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
			if seenKnown[code] {
				return nil, fmt.Errorf("variable part: %w", ErrDuplicateKnownParameter)
			}
			seenKnown[code] = true
			r.callingSelector = value
		case ParamCalledSelector:
			if seenKnown[code] {
				return nil, fmt.Errorf("variable part: %w", ErrDuplicateKnownParameter)
			}
			seenKnown[code] = true
			r.calledSelector = value
		case ParamTPDUSize:
			if seenKnown[code] {
				return nil, fmt.Errorf("variable part: %w", ErrDuplicateKnownParameter)
			}
			seenKnown[code] = true
			if length != 1 {
				return nil, fmt.Errorf("variable part: TPDU size length %d: %w", length, ErrUnexpectedParameterLength)
			}
			v := value[0]
			r.tpduSize = &v
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
