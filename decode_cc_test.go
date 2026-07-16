// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"testing"
)

var minimalCC = []byte{0x06, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00}

func TestDecodeCC(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, cc *CC)
	}{
		{
			name:    "minimal",
			b:       minimalCC,
			wantErr: nil,
			check: func(t *testing.T, cc *CC) {
				if cc.DestinationRef != 1 || cc.SourceRef != 2 || cc.ClassOption != 0 {
					t.Errorf("DST=%d SRC=%d Class=%d", cc.DestinationRef, cc.SourceRef, cc.ClassOption)
				}
			},
		},
		{
			name:    "too short",
			b:       []byte{0x06, 0xD0, 0x00},
			wantErr: ErrTooShort,
		},
		{
			name:    "wrong type",
			b:       []byte{0x06, 0xE0, 0x00, 0x01, 0x00, 0x02, 0x00},
			wantErr: ErrInvalidTPDUCode,
		},
		{
			name:    "with variable part (calling selector)",
			b:       []byte{0x0a, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00, 0xC1, 0x02, 0x01, 0x02}, // LI=10, fixed 6, C1 len 2
			wantErr: nil,
			check: func(t *testing.T, cc *CC) {
				if cc.CallingSelector == nil || len(cc.CallingSelector) != 2 || cc.CallingSelector[0] != 0x01 {
					t.Errorf("CallingSelector = %v", cc.CallingSelector)
				}
				if cc.CalledSelector != nil {
					t.Errorf("CalledSelector = %v", cc.CalledSelector)
				}
			},
		},
		{
			name:    "header length exceeds buffer",
			b:       []byte{0x0a, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00}, // LI=10 but only 7 bytes
			wantErr: ErrTooShort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc, err := DecodeCC(tt.b)
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
				tt.check(t, cc)
			}
		})
	}
}
