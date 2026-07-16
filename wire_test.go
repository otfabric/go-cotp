// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"testing"
)

func TestReadLI(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantLI  uint8
		wantErr error
	}{
		{"empty", nil, 0, ErrTooShort},
		{"empty slice", []byte{}, 0, ErrTooShort},
		{"LI 0", []byte{0x00}, 0, nil},
		{"LI 6", []byte{0x06}, 6, nil},
		{"LI 254", []byte{0xFE}, 254, nil},
		{"LI 255 invalid", []byte{0xFF}, 0, ErrInvalidLI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadLI(tt.b)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ReadLI() err = %v, want %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil && got != tt.wantLI {
				t.Errorf("ReadLI() = %d, want %d", got, tt.wantLI)
			}
		})
	}
}

func TestHeaderLength(t *testing.T) {
	tests := []struct {
		name       string
		b          []byte
		wantLength int
		wantErr    error
	}{
		{"too short for LI", []byte{}, 0, ErrTooShort},
		{"LI 5 but only 3 bytes", []byte{0x05, 0x00, 0x00}, 0, ErrTooShort},
		{"LI 0", []byte{0x00}, 1, nil},
		{"LI 5, 6 bytes", []byte{0x05, 1, 2, 3, 4, 5}, 6, nil},
		{"LI 254", []byte{0xFE}, 255, ErrTooShort}, // need 255 bytes, have 1
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HeaderLength(tt.b)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("HeaderLength() err = %v, want %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil && got != tt.wantLength {
				t.Errorf("HeaderLength() = %d, want %d", got, tt.wantLength)
			}
		})
	}
}

func TestPeekType(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		want    TPDUType
		wantErr error
	}{
		// Too short
		{"0 bytes", nil, 0, ErrTooShort},
		{"1 byte", []byte{0x00}, 0, ErrTooShort},
		// Supported types: LI=0 or minimal, then type code in octet 2
		{"CR", []byte{0x00, 0xE0}, TypeCR, nil},
		{"CC", []byte{0x00, 0xD0}, TypeCC, nil},
		{"DR", []byte{0x00, 0x80}, TypeDR, nil},
		{"DC", []byte{0x00, 0xC0}, TypeDC, nil},
		{"DT", []byte{0x00, 0xF0}, TypeDT, nil},
		{"DT with ROA", []byte{0x00, 0xF1}, TypeDT, nil},
		{"ER", []byte{0x00, 0x70}, TypeER, nil},
		// ED, AK, EA, RJ (Phase 7)
		{"ED", []byte{0x00, 0x10}, TypeED, nil},
		{"AK", []byte{0x00, 0x60}, TypeAK, nil},
		{"AK with CDT", []byte{0x00, 0x63}, TypeAK, nil},
		{"EA", []byte{0x00, 0x20}, TypeEA, nil},
		{"RJ", []byte{0x00, 0x50}, TypeRJ, nil},
		{"RJ with CDT", []byte{0x00, 0x5F}, TypeRJ, nil},
		// Invalid / reserved
		{"LI 255", []byte{0xFF, 0xE0}, 0, ErrInvalidLI},
		{"reserved 0x00", []byte{0x00, 0x00}, 0, ErrReservedTPDU},
		{"reserved 0x30", []byte{0x00, 0x30}, 0, ErrReservedTPDU},
		{"invalid 0x90", []byte{0x00, 0x90}, 0, ErrInvalidTPDUCode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PeekType(tt.b)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("PeekType() err = nil, want %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("PeekType() err = %v, want Is(%v)", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("PeekType() err = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("PeekType() = %v (%s), want %v (%s)", got, got, tt.want, tt.want)
			}
		})
	}
}
