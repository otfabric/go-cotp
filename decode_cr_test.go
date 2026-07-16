// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"testing"
)

// Minimal valid CR: LI=6 (fixed part only), code 0xE0, DST=0, SRC=0, ClassOption=0.
var minimalCR = []byte{0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}

func TestDecodeCR(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, cr *CR)
	}{
		{
			name:    "minimal",
			b:       minimalCR,
			wantErr: nil,
			check: func(t *testing.T, cr *CR) {
				if cr.CDT != 0 || cr.DestinationRef != 0 || cr.SourceRef != 0 || cr.ClassOption != 0 {
					t.Errorf("fixed part: CDT=%d DST=%d SRC=%d Class=%d", cr.CDT, cr.DestinationRef, cr.SourceRef, cr.ClassOption)
				}
				if len(cr.Parameters) != 0 {
					t.Errorf("parameters = %v", cr.Parameters)
				}
			},
		},
		{
			name:    "with selector and TPDU size",
			b:       []byte{0x10, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC1, 2, 0x01, 0x02, 0xC2, 1, 0x03, 0xC0, 1, 0x07},
			wantErr: nil,
			check: func(t *testing.T, cr *CR) {
				if len(cr.CallingSelector) != 2 || cr.CallingSelector[0] != 0x01 {
					t.Errorf("CallingSelector = %v", cr.CallingSelector)
				}
				if len(cr.CalledSelector) != 1 || cr.CalledSelector[0] != 0x03 {
					t.Errorf("CalledSelector = %v", cr.CalledSelector)
				}
				if cr.TPDUSize == nil || *cr.TPDUSize != 0x07 {
					t.Errorf("TPDUSize = %v", cr.TPDUSize)
				}
			},
		},
		{
			name:    "with unknown param",
			b:       []byte{0x0A, 0xE1, 0x00, 0x00, 0x12, 0x34, 0x00, 0x99, 2, 0xAA, 0xBB},
			wantErr: nil,
			check: func(t *testing.T, cr *CR) {
				if len(cr.Parameters) != 1 || cr.Parameters[0].Code != 0x99 || len(cr.Parameters[0].Value) != 2 {
					t.Errorf("parameters = %v", cr.Parameters)
				}
			},
		},
		{
			name:    "too short",
			b:       []byte{0x06, 0xE0, 0x00, 0x00},
			wantErr: ErrTooShort,
		},
		{
			name:    "wrong type code",
			b:       []byte{0x06, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: ErrInvalidTPDUCode,
		},
		{
			name:    "duplicate 0xC1",
			b:       []byte{0x0C, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 1, 0x01, 0xC1, 1, 0x02},
			wantErr: ErrDuplicateKnownParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := DecodeCR(tt.b)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("err = %v, want Is(%v)", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cr)
			}
		})
	}
}
