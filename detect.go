// SPDX-License-Identifier: MIT

package cotp

// LooksLikeCR returns true if b appears to be a CR TPDU: valid LI, buffer long enough, and type code 0xE0..0xEF.
// It validates LI first so junk buffers do not pass by masking alone.
func LooksLikeCR(b []byte) bool {
	if len(b) < MinHeaderLength {
		return false
	}
	li, err := ReadLI(b)
	if err != nil {
		return false
	}
	if len(b) < 1+int(li) {
		return false
	}
	return b[1]&0xF0 == 0xE0
}

// LooksLikeCC returns true if b appears to be a CC TPDU: valid LI, buffer long enough, and type code 0xD0..0xDF.
func LooksLikeCC(b []byte) bool {
	if len(b) < MinHeaderLength {
		return false
	}
	li, err := ReadLI(b)
	if err != nil {
		return false
	}
	if len(b) < 1+int(li) {
		return false
	}
	return b[1]&0xF0 == 0xD0
}

// LooksLikeDR returns true if b appears to be a DR TPDU (classification only: valid LI, buffer length, type 0x80).
func LooksLikeDR(b []byte) bool {
	if len(b) < MinHeaderLength {
		return false
	}
	li, err := ReadLI(b)
	if err != nil {
		return false
	}
	if len(b) < 1+int(li) {
		return false
	}
	return b[1] == 0x80
}

// LooksLikeDC returns true if b appears to be a DC TPDU (classification only: valid LI, buffer length, type 0xC0).
func LooksLikeDC(b []byte) bool {
	if len(b) < MinHeaderLength {
		return false
	}
	li, err := ReadLI(b)
	if err != nil {
		return false
	}
	if len(b) < 1+int(li) {
		return false
	}
	return b[1] == 0xC0
}

// LooksLikeDT returns true if b appears to be a DT TPDU (classification only: valid LI, buffer length, type 0xF0..0xF1).
// The type mask matches PeekType and Decode (1111 000y), not the full high nibble.
func LooksLikeDT(b []byte) bool {
	if len(b) < MinHeaderLength {
		return false
	}
	li, err := ReadLI(b)
	if err != nil {
		return false
	}
	if len(b) < 1+int(li) {
		return false
	}
	return b[1]&0xFE == 0xF0
}

// LooksLikeER returns true if b appears to be an ER TPDU (classification only: valid LI, buffer length, type 0x70).
func LooksLikeER(b []byte) bool {
	if len(b) < MinHeaderLength {
		return false
	}
	li, err := ReadLI(b)
	if err != nil {
		return false
	}
	if len(b) < 1+int(li) {
		return false
	}
	return b[1] == 0x70
}

// IsConnectionOriented returns true if b appears to be a connection-related TPDU (CR, CC, DR, or DC).
// It uses PeekType after validating LI; no full decode.
func IsConnectionOriented(b []byte) bool {
	t, err := PeekType(b)
	if err != nil {
		return false
	}
	switch t {
	case TypeCR, TypeCC, TypeDR, TypeDC:
		return true
	default:
		return false
	}
}

// LooksLikeED returns true if b appears to be an ED TPDU (classification only: valid LI, buffer length, type 0x10).
func LooksLikeED(b []byte) bool {
	if len(b) < MinHeaderLength {
		return false
	}
	li, err := ReadLI(b)
	if err != nil {
		return false
	}
	if len(b) < 1+int(li) {
		return false
	}
	return b[1] == 0x10
}

// LooksLikeAK returns true if b appears to be an AK TPDU (classification only: valid LI, buffer length, type 0x60..0x6F).
func LooksLikeAK(b []byte) bool {
	if len(b) < MinHeaderLength {
		return false
	}
	li, err := ReadLI(b)
	if err != nil {
		return false
	}
	if len(b) < 1+int(li) {
		return false
	}
	return b[1]&0xF0 == 0x60
}

// LooksLikeEA returns true if b appears to be an EA TPDU (classification only: valid LI, buffer length, type 0x20).
func LooksLikeEA(b []byte) bool {
	if len(b) < MinHeaderLength {
		return false
	}
	li, err := ReadLI(b)
	if err != nil {
		return false
	}
	if len(b) < 1+int(li) {
		return false
	}
	return b[1] == 0x20
}

// LooksLikeRJ returns true if b appears to be an RJ TPDU (classification only: valid LI, buffer length, type 0x50..0x5F).
func LooksLikeRJ(b []byte) bool {
	if len(b) < MinHeaderLength {
		return false
	}
	li, err := ReadLI(b)
	if err != nil {
		return false
	}
	if len(b) < 1+int(li) {
		return false
	}
	return b[1]&0xF0 == 0x50
}

// IsAckType returns true if t is an acknowledgment-related TPDU type (AK or RJ).
// For classification after decode; use when you already have Decoded.Type.
func IsAckType(t TPDUType) bool {
	return t == TypeAK || t == TypeRJ
}
