// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"errors"
	"testing"
)

func TestExtractUserData(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		want    []byte
		wantErr error
	}{
		{
			name:    "minimal DT no user data",
			b:       minimalDT,
			want:    []byte{},
			wantErr: nil,
		},
		{
			name:    "minimal DT with user data",
			b:       []byte{0x02, 0xF0, 0x00, 0xDE, 0xAD, 0xBE, 0xEF},
			want:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
			wantErr: nil,
		},
		{
			name:    "CR returns error",
			b:       minimalCR,
			want:    nil,
			wantErr: ErrInvalidTPDUCode,
		},
		{
			name:    "CC returns error",
			b:       minimalCC,
			want:    nil,
			wantErr: ErrInvalidTPDUCode,
		},
		{
			name:    "ED returns user data",
			b:       minimalED,
			want:    []byte{0x01},
			wantErr: nil,
		},
		{
			name:    "ED with 2 byte user data",
			b:       []byte{0x04, 0x10, 0x00, 0x00, 0x00, 0xDE, 0xAD},
			want:    []byte{0xDE, 0xAD},
			wantErr: nil,
		},
		{
			name:    "too short",
			b:       []byte{0x01},
			want:    nil,
			wantErr: ErrTooShort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractUserData(tt.b)
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
			if !bytes.Equal(got, tt.want) {
				t.Errorf("ExtractUserData() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestExtractUserData_SameAsDecodeDT(t *testing.T) {
	b := []byte{0x02, 0xF0, 0x00, 0x11, 0x22}
	extracted, err := ExtractUserData(b)
	if err != nil {
		t.Fatalf("ExtractUserData: %v", err)
	}
	dt, err := DecodeDT(b)
	if err != nil {
		t.Fatalf("DecodeDT: %v", err)
	}
	if !bytes.Equal(extracted, dt.UserData) {
		t.Errorf("ExtractUserData = %x, DecodeDT.UserData = %x", extracted, dt.UserData)
	}
}
