package cotp

import "fmt"

// ReadLI returns the length indicator from the first octet of b.
// LI is the header length in octets excluding the LI octet itself and user data (X.224).
// Valid range is 0–254. Returns ErrTooShort if len(b) < 1, ErrInvalidLI if LI > 254.
func ReadLI(b []byte) (uint8, error) {
	if len(b) < 1 {
		return 0, fmt.Errorf("read LI: %w", ErrTooShort)
	}
	li := b[0]
	if li > MaxLI {
		return 0, fmt.Errorf("read LI: value %d: %w", li, ErrInvalidLI)
	}
	return li, nil
}

// HeaderLength returns the total header length in octets: 1 (LI) + LI value.
// So the header occupies b[0 : 1+LI]. Returns an error if b is too short or LI is invalid.
func HeaderLength(b []byte) (int, error) {
	li, err := ReadLI(b)
	if err != nil {
		return 0, err
	}
	headerLen := 1 + int(li)
	if len(b) < headerLen {
		return 0, fmt.Errorf("header length: need %d bytes, have %d: %w", headerLen, len(b), ErrTooShort)
	}
	return headerLen, nil
}

// PeekType classifies the TPDU from the first two octets (LI and type code).
// It performs only minimal LI sanity; full header/variable-part validation is done by per-TPDU decoders.
// Returns TypeED, TypeAK, TypeEA, TypeRJ for those codes; reserved/invalid codes return ErrInvalidTPDUCode or ErrReservedTPDU.
func PeekType(b []byte) (TPDUType, error) {
	if len(b) < MinHeaderLength {
		return 0, fmt.Errorf("peek type: %w", ErrTooShort)
	}
	_, err := ReadLI(b)
	if err != nil {
		return 0, fmt.Errorf("peek type: %w", err)
	}
	code := b[1]

	switch {
	case code&0xF0 == 0xE0:
		return TypeCR, nil
	case code&0xF0 == 0xD0:
		return TypeCC, nil
	case code == 0x80:
		return TypeDR, nil
	case code == 0xC0:
		return TypeDC, nil
	case code&0xFE == 0xF0: // 1111 000y
		return TypeDT, nil
	case code == 0x70:
		return TypeER, nil
	case code == 0x10:
		return TypeED, nil
	case code&0xF0 == 0x60:
		return TypeAK, nil
	case code == 0x20:
		return TypeEA, nil
	case code&0xF0 == 0x50:
		return TypeRJ, nil
	case code == 0x00 || code == 0x30:
		return 0, fmt.Errorf("peek type: reserved code 0x%02x: %w", code, ErrReservedTPDU)
	default:
		return 0, fmt.Errorf("peek type: invalid code 0x%02x: %w", code, ErrInvalidTPDUCode)
	}
}
