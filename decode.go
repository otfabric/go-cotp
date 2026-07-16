// SPDX-License-Identifier: MIT

package cotp

import "fmt"

// Decode parses a complete COTP TPDU from b and returns a Decoded struct.
// On success, exactly one of CR, CC, DT, DR, DC, ER, ED, AK, EA, RJ is non-nil and Type matches it.
// On error, the returned Decoded is the zero value; it is never partially filled.
func Decode(b []byte) (Decoded, error) {
	if len(b) < MinHeaderLength {
		return Decoded{}, fmt.Errorf("decode: %w", ErrTooShort)
	}
	t, err := PeekType(b)
	if err != nil {
		return Decoded{}, fmt.Errorf("decode: %w", err)
	}

	var d Decoded
	switch t {
	case TypeCR:
		cr, err := DecodeCR(b)
		if err != nil {
			return Decoded{}, fmt.Errorf("decode: %w", err)
		}
		d.Type = TypeCR
		d.CR = cr
	case TypeCC:
		cc, err := DecodeCC(b)
		if err != nil {
			return Decoded{}, fmt.Errorf("decode: %w", err)
		}
		d.Type = TypeCC
		d.CC = cc
	case TypeDT:
		dt, err := DecodeDT(b)
		if err != nil {
			return Decoded{}, fmt.Errorf("decode: %w", err)
		}
		d.Type = TypeDT
		d.DT = dt
	case TypeDR:
		dr, err := DecodeDR(b)
		if err != nil {
			return Decoded{}, fmt.Errorf("decode: %w", err)
		}
		d.Type = TypeDR
		d.DR = dr
	case TypeDC:
		dc, err := DecodeDC(b)
		if err != nil {
			return Decoded{}, fmt.Errorf("decode: %w", err)
		}
		d.Type = TypeDC
		d.DC = dc
	case TypeER:
		er, err := DecodeER(b)
		if err != nil {
			return Decoded{}, fmt.Errorf("decode: %w", err)
		}
		d.Type = TypeER
		d.ER = er
	case TypeED:
		ed, err := DecodeED(b)
		if err != nil {
			return Decoded{}, fmt.Errorf("decode: %w", err)
		}
		d.Type = TypeED
		d.ED = ed
	case TypeAK:
		ak, err := DecodeAK(b)
		if err != nil {
			return Decoded{}, fmt.Errorf("decode: %w", err)
		}
		d.Type = TypeAK
		d.AK = ak
	case TypeEA:
		ea, err := DecodeEA(b)
		if err != nil {
			return Decoded{}, fmt.Errorf("decode: %w", err)
		}
		d.Type = TypeEA
		d.EA = ea
	case TypeRJ:
		rj, err := DecodeRJ(b)
		if err != nil {
			return Decoded{}, fmt.Errorf("decode: %w", err)
		}
		d.Type = TypeRJ
		d.RJ = rj
	default:
		return Decoded{}, fmt.Errorf("decode: %w", ErrUnsupportedTPDU)
	}
	return d, nil
}
