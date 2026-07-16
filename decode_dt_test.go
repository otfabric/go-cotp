// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"errors"
	"testing"
)

// Minimal DT: LI=2, DT+ROA=0xF0, TPDU-NR+EOT=0x00.
var minimalDT = []byte{0x02, 0xF0, 0x00}

func TestDecodeDT(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, dt *DT)
	}{
		{
			name:    "minimal",
			b:       minimalDT,
			wantErr: nil,
			check: func(t *testing.T, dt *DT) {
				if dt.DestinationRef != nil {
					t.Errorf("DestinationRef should be nil for minimal")
				}
				if dt.TPDUNR == nil || *dt.TPDUNR != 0 {
					t.Errorf("TPDUNR = %v", dt.TPDUNR)
				}
				if dt.EOT {
					t.Error("EOT should be false")
				}
				if len(dt.Parameters) != 0 {
					t.Errorf("Parameters = %v", dt.Parameters)
				}
				if len(dt.UserData) != 0 {
					t.Errorf("UserData = %v", dt.UserData)
				}
			},
		},
		{
			name:    "minimal with user data",
			b:       []byte{0x02, 0xF0, 0x00, 0xDE, 0xAD},
			wantErr: nil,
			check: func(t *testing.T, dt *DT) {
				if !bytes.Equal(dt.UserData, []byte{0xDE, 0xAD}) {
					t.Errorf("UserData = %v", dt.UserData)
				}
			},
		},
		{
			name:    "minimal EOT set",
			b:       []byte{0x02, 0xF0, 0x80},
			wantErr: nil,
			check: func(t *testing.T, dt *DT) {
				if !dt.EOT {
					t.Error("EOT should be true")
				}
				if dt.TPDUNR == nil || *dt.TPDUNR != 0 {
					t.Errorf("TPDUNR = %v", dt.TPDUNR)
				}
			},
		},
		{
			name:    "normal with DST-REF and user data",
			b:       []byte{0x04, 0xF0, 0x12, 0x34, 0x01, 0xAB, 0xCD},
			wantErr: nil,
			check: func(t *testing.T, dt *DT) {
				if dt.DestinationRef == nil || *dt.DestinationRef != 0x1234 {
					t.Errorf("DestinationRef = %v", dt.DestinationRef)
				}
				if dt.TPDUNR == nil || *dt.TPDUNR != 1 {
					t.Errorf("TPDUNR = %v", dt.TPDUNR)
				}
				if !bytes.Equal(dt.UserData, []byte{0xAB, 0xCD}) {
					t.Errorf("UserData = %v", dt.UserData)
				}
			},
		},
		{
			name:    "empty user data (normal)",
			b:       []byte{0x04, 0xF0, 0x00, 0x00, 0x00},
			wantErr: nil,
			check: func(t *testing.T, dt *DT) {
				if len(dt.UserData) != 0 {
					t.Errorf("UserData = %v", dt.UserData)
				}
			},
		},
		{
			name:    "too short",
			b:       []byte{0x02, 0xF0},
			wantErr: ErrTooShort,
		},
		{
			name:    "wrong type code",
			b:       []byte{0x02, 0xE0, 0x00},
			wantErr: ErrInvalidTPDUCode,
		},
		{
			name:    "LI=3 unsupported variant",
			b:       []byte{0x03, 0xF0, 0x00, 0xFF},
			wantErr: ErrUnsupportedDTVariant,
		},
		{
			name:    "LI=1 unsupported",
			b:       []byte{0x01, 0xF0},
			wantErr: ErrUnsupportedDTVariant,
		},
		{
			name:    "normal with variable part",
			b:       []byte{0x06, 0xF0, 0x00, 0x01, 0x80, 0x99, 0x00}, // LI=6: fixed 4 (DST=1, NR=0 EOT=1) + param 2
			wantErr: nil,
			check: func(t *testing.T, dt *DT) {
				if dt.DestinationRef == nil || *dt.DestinationRef != 1 {
					t.Errorf("DestinationRef = %v", dt.DestinationRef)
				}
				if len(dt.Parameters) != 1 {
					t.Errorf("Parameters = %v", dt.Parameters)
				}
			},
		},
		{
			name:    "header length exceeds buffer",
			b:       []byte{0x05, 0xF0, 0x00, 0x01, 0x00}, // LI=5 but only 5 bytes (need 6)
			wantErr: ErrTooShort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dt, err := DecodeDT(tt.b)
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
				tt.check(t, dt)
			}
		})
	}
}

func TestDT_MarshalBinary_RoundTrip(t *testing.T) {
	dt, err := DecodeDT(minimalDT)
	if err != nil {
		t.Fatalf("DecodeDT: %v", err)
	}
	out, err := dt.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(out, minimalDT) {
		t.Errorf("round-trip:\n got %x\nwant %x", out, minimalDT)
	}
}

func TestDT_MarshalBinary_WithUserData(t *testing.T) {
	dt := &DT{
		EOT:      false,
		TPDUNR:   bytePtr(1),
		UserData: []byte{0xCA, 0xFE},
	}
	out, err := dt.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	dt2, err := DecodeDT(out)
	if err != nil {
		t.Fatalf("DecodeDT: %v", err)
	}
	if !bytes.Equal(dt2.UserData, dt.UserData) {
		t.Errorf("UserData: got %x want %x", dt2.UserData, dt.UserData)
	}
	if dt2.TPDUNR == nil || *dt2.TPDUNR != *dt.TPDUNR {
		t.Errorf("TPDUNR: got %v", dt2.TPDUNR)
	}
}

func TestDT_MarshalBinary_EmptyUserData(t *testing.T) {
	dt := &DT{EOT: false, UserData: []byte{}}
	out, err := dt.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("expected 3 bytes, got %d", len(out))
	}
}

func TestDT_MarshalBinary_NilUserData(t *testing.T) {
	dt := &DT{EOT: false, UserData: nil}
	out, err := dt.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("expected 3 bytes, got %d", len(out))
	}
}

func TestDT_MarshalBinary_Deterministic(t *testing.T) {
	dt := &DT{EOT: true, TPDUNR: bytePtr(5), UserData: []byte{1, 2, 3}}
	out1, _ := dt.MarshalBinary()
	out2, _ := dt.MarshalBinary()
	if !bytes.Equal(out1, out2) {
		t.Errorf("deterministic: %x != %x", out1, out2)
	}
}

func TestDT_MarshalBinary_NormalRoundTrip(t *testing.T) {
	ref := uint16(0x1234)
	dt := &DT{
		EOT:            true,
		TPDUNR:         bytePtr(7),
		DestinationRef: &ref,
		UserData:       []byte{0xAA},
	}
	out, err := dt.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	dt2, err := DecodeDT(out)
	if err != nil {
		t.Fatalf("DecodeDT: %v", err)
	}
	if dt2.DestinationRef == nil || *dt2.DestinationRef != *dt.DestinationRef {
		t.Errorf("DestinationRef: got %v", dt2.DestinationRef)
	}
	if !dt2.EOT || dt2.TPDUNR == nil || *dt2.TPDUNR != 7 {
		t.Errorf("EOT/TPDUNR: %v %v", dt2.EOT, dt2.TPDUNR)
	}
	if !bytes.Equal(dt2.UserData, dt.UserData) {
		t.Errorf("UserData: got %x", dt2.UserData)
	}
}
