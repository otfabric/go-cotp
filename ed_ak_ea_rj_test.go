// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"errors"
	"testing"
)

var (
	// Minimal ED: LI=4, code=0x10, DST=0, NR+EOT=0, user data 1 octet (required 1-16).
	minimalED = []byte{0x04, 0x10, 0x00, 0x00, 0x00, 0x01}
	// Minimal AK: LI=4, code=0x60, DST=0, YRTUNR=0.
	minimalAK = []byte{0x04, 0x60, 0x00, 0x00, 0x00}
	// Minimal EA: LI=4, code=0x20, DST=0, YREDTUNR=0.
	minimalEA = []byte{0x04, 0x20, 0x00, 0x00, 0x00}
	// Minimal RJ: LI=4, code=0x50, DST=0, YRTUNR=0.
	minimalRJ = []byte{0x04, 0x50, 0x00, 0x00, 0x00}
)

func TestDecodeED(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, ed *ED)
	}{
		{
			name:    "minimal",
			b:       minimalED,
			wantErr: nil,
			check: func(t *testing.T, ed *ED) {
				if ed.DestinationRef == nil || *ed.DestinationRef != 0 {
					t.Errorf("DestinationRef = %v", ed.DestinationRef)
				}
				if ed.TPDUNR == nil || *ed.TPDUNR != 0 {
					t.Errorf("TPDUNR = %v", ed.TPDUNR)
				}
				if ed.EOT {
					t.Error("EOT should be false")
				}
				if len(ed.UserData) != 1 || ed.UserData[0] != 0x01 {
					t.Errorf("UserData = %v", ed.UserData)
				}
			},
		},
		{
			name:    "with user data 2 bytes",
			b:       []byte{0x04, 0x10, 0x12, 0x34, 0x81, 0xDE, 0xAD}, // DST=0x1234, NR=1, EOT=true, userdata DE AD
			wantErr: nil,
			check: func(t *testing.T, ed *ED) {
				if ed.DestinationRef == nil || *ed.DestinationRef != 0x1234 {
					t.Errorf("DestinationRef = %v", ed.DestinationRef)
				}
				if ed.TPDUNR == nil || *ed.TPDUNR != 1 {
					t.Errorf("TPDUNR = %v", ed.TPDUNR)
				}
				if !ed.EOT {
					t.Error("EOT should be true")
				}
				if !bytes.Equal(ed.UserData, []byte{0xDE, 0xAD}) {
					t.Errorf("UserData = %v", ed.UserData)
				}
			},
		},
		{
			name:    "user data too short (0)",
			b:       []byte{0x04, 0x10, 0x00, 0x00, 0x00},
			wantErr: ErrInvalidEDUserDataLength,
		},
		{
			name:    "too short",
			b:       []byte{0x04, 0x10, 0x00},
			wantErr: ErrTooShort,
		},
		{
			name:    "wrong type",
			b:       []byte{0x04, 0x20, 0x00, 0x00, 0x00, 0x01},
			wantErr: ErrInvalidTPDUCode,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ed, err := DecodeED(tt.b)
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
				tt.check(t, ed)
			}
		})
	}
}

func TestDecodeAK(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, ak *AK)
	}{
		{
			name:    "minimal",
			b:       minimalAK,
			wantErr: nil,
			check: func(t *testing.T, ak *AK) {
				if ak.CDT != 0 || ak.DestinationRef != 0 || ak.YRTUNR != 0 {
					t.Errorf("CDT=%d DST=%d YRTUNR=%d", ak.CDT, ak.DestinationRef, ak.YRTUNR)
				}
			},
		},
		{
			name:    "CDT in low nibble",
			b:       []byte{0x04, 0x63, 0x00, 0x01, 0x05}, // CDT=3, DST=1, YRTUNR=5
			wantErr: nil,
			check: func(t *testing.T, ak *AK) {
				if ak.CDT != 3 || ak.DestinationRef != 1 || ak.YRTUNR != 5 {
					t.Errorf("CDT=%d DST=%d YRTUNR=%d", ak.CDT, ak.DestinationRef, ak.YRTUNR)
				}
			},
		},
		{
			name:    "wrong type",
			b:       []byte{0x04, 0x50, 0x00, 0x00, 0x00},
			wantErr: ErrInvalidTPDUCode,
		},
		{
			name:    "with variable part (unknown param)",
			b:       []byte{0x08, 0x60, 0x00, 0x01, 0x02, 0x99, 0x02, 0xAA, 0xBB}, // LI=8: fixed 4 + param 0x99 len 2 (4 bytes)
			wantErr: nil,
			check: func(t *testing.T, ak *AK) {
				if ak.CDT != 0 || ak.DestinationRef != 1 || ak.YRTUNR != 2 {
					t.Errorf("CDT=%d DST=%d YRTUNR=%d", ak.CDT, ak.DestinationRef, ak.YRTUNR)
				}
				if len(ak.Parameters) != 1 || ak.Parameters[0].Code != 0x99 || !bytes.Equal(ak.Parameters[0].Value, []byte{0xAA, 0xBB}) {
					t.Errorf("Parameters = %v", ak.Parameters)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ak, err := DecodeAK(tt.b)
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
				tt.check(t, ak)
			}
		})
	}
}

func TestDecodeEA(t *testing.T) {
	ea, err := DecodeEA(minimalEA)
	if err != nil {
		t.Fatalf("DecodeEA: %v", err)
	}
	if ea.DestinationRef != 0 || ea.YREDTUNR != 0 {
		t.Errorf("DST=%d YREDTUNR=%d", ea.DestinationRef, ea.YREDTUNR)
	}
	_, err = DecodeEA([]byte{0x04, 0x60, 0x00, 0x00, 0x00})
	if err == nil || !errors.Is(err, ErrInvalidTPDUCode) {
		t.Errorf("wrong type should fail: %v", err)
	}
	// EA with variable part (LI=6: fixed 4 + 2 bytes = code+len for param 0x99 len 0)
	ea, err = DecodeEA([]byte{0x06, 0x20, 0x00, 0x01, 0x02, 0x99, 0x00}) // header 7 bytes
	if err != nil {
		t.Fatalf("DecodeEA with variable part: %v", err)
	}
	if ea.DestinationRef != 1 || ea.YREDTUNR != 2 {
		t.Errorf("DST=%d YREDTUNR=%d", ea.DestinationRef, ea.YREDTUNR)
	}
	if len(ea.Parameters) != 1 || ea.Parameters[0].Code != 0x99 {
		t.Errorf("Parameters = %v", ea.Parameters)
	}
}

func TestDecodeRJ(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, rj *RJ)
	}{
		{
			name:    "minimal",
			b:       minimalRJ,
			wantErr: nil,
			check: func(t *testing.T, rj *RJ) {
				if rj.CDT != 0 || rj.DestinationRef != 0 || rj.YRTUNR != 0 {
					t.Errorf("CDT=%d DST=%d YRTUNR=%d", rj.CDT, rj.DestinationRef, rj.YRTUNR)
				}
			},
		},
		{
			name:    "LI>4 rejects (variable part not allowed)",
			b:       []byte{0x05, 0x50, 0x00, 0x00, 0x00, 0xFF},
			wantErr: ErrMalformedParameter,
		},
		{
			name:    "wrong type",
			b:       []byte{0x04, 0x60, 0x00, 0x00, 0x00},
			wantErr: ErrInvalidTPDUCode,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rj, err := DecodeRJ(tt.b)
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
				tt.check(t, rj)
			}
		})
	}
}

func TestED_MarshalBinary_RoundTrip(t *testing.T) {
	ed, err := DecodeED(minimalED)
	if err != nil {
		t.Fatalf("DecodeED: %v", err)
	}
	out, err := ed.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(out, minimalED) {
		t.Errorf("round-trip: got %x want %x", out, minimalED)
	}
}

func TestED_MarshalBinary_MissingRequiredFields(t *testing.T) {
	// Nil DestinationRef or TPDUNR must return ErrMissingRequiredField.
	ed := &ED{UserData: []byte{0x01}}
	_, err := ed.MarshalBinary()
	if err == nil || !errors.Is(err, ErrMissingRequiredField) {
		t.Errorf("nil required fields: got %v, want ErrMissingRequiredField", err)
	}
	dst := uint16(0)
	ed = &ED{DestinationRef: &dst, UserData: []byte{0x01}}
	_, err = ed.MarshalBinary()
	if err == nil || !errors.Is(err, ErrMissingRequiredField) {
		t.Errorf("nil TPDUNR: got %v, want ErrMissingRequiredField", err)
	}
}

func TestED_MarshalBinary_UserDataRange(t *testing.T) {
	dst := uint16(0)
	nr := uint8(0)
	ed := &ED{DestinationRef: &dst, TPDUNR: &nr, UserData: []byte{}}
	_, err := ed.MarshalBinary()
	if err == nil || !errors.Is(err, ErrInvalidEDUserDataLength) {
		t.Errorf("empty user data should fail: %v", err)
	}
	ed.UserData = make([]byte, 17)
	_, err = ed.MarshalBinary()
	if err == nil || !errors.Is(err, ErrInvalidEDUserDataLength) {
		t.Errorf("17-byte user data should fail: %v", err)
	}
}

func TestED_MarshalBinary_WithParams(t *testing.T) {
	dst := uint16(1)
	nr := uint8(0)
	ed := &ED{DestinationRef: &dst, TPDUNR: &nr, UserData: []byte{0x01}, Parameters: []Parameter{{Code: 0x99, Value: []byte{0xAA}}}}
	out, err := ed.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	ed2, err := DecodeED(out)
	if err != nil {
		t.Fatalf("DecodeED: %v", err)
	}
	if len(ed2.Parameters) != 1 || !bytes.Equal(ed2.Parameters[0].Value, []byte{0xAA}) {
		t.Errorf("Parameters = %v", ed2.Parameters)
	}
}

func TestED_MarshalBinary_ParamValueTooLong(t *testing.T) {
	dst := uint16(0)
	nr := uint8(0)
	ed := &ED{DestinationRef: &dst, TPDUNR: &nr, UserData: []byte{0x01}, Parameters: []Parameter{{Code: 0x99, Value: make([]byte, 256)}}}
	_, err := ed.MarshalBinary()
	if err == nil || !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Errorf("expected ErrUnexpectedParameterLength, got %v", err)
	}
}

func TestAK_MarshalBinary_RoundTrip(t *testing.T) {
	ak, err := DecodeAK(minimalAK)
	if err != nil {
		t.Fatalf("DecodeAK: %v", err)
	}
	out, err := ak.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(out, minimalAK) {
		t.Errorf("round-trip: got %x want %x", out, minimalAK)
	}
}

func TestAK_MarshalBinary_WithParams(t *testing.T) {
	ak := &AK{DestinationRef: 1, CDT: 0, YRTUNR: 2, Parameters: []Parameter{{Code: 0x99, Value: []byte{0xAA}}}}
	out, err := ak.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	ak2, err := DecodeAK(out)
	if err != nil {
		t.Fatalf("DecodeAK: %v", err)
	}
	if len(ak2.Parameters) != 1 || !bytes.Equal(ak2.Parameters[0].Value, []byte{0xAA}) {
		t.Errorf("Parameters = %v", ak2.Parameters)
	}
}

func TestAK_MarshalBinary_ParamValueTooLong(t *testing.T) {
	ak := &AK{Parameters: []Parameter{{Code: 0x99, Value: make([]byte, 256)}}}
	_, err := ak.MarshalBinary()
	if err == nil || !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Errorf("expected ErrUnexpectedParameterLength, got %v", err)
	}
}

func TestEA_MarshalBinary_RoundTrip(t *testing.T) {
	ea, err := DecodeEA(minimalEA)
	if err != nil {
		t.Fatalf("DecodeEA: %v", err)
	}
	out, err := ea.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(out, minimalEA) {
		t.Errorf("round-trip: got %x want %x", out, minimalEA)
	}
}

func TestEA_MarshalBinary_WithParams(t *testing.T) {
	ea := &EA{DestinationRef: 1, YREDTUNR: 2, Parameters: []Parameter{{Code: 0x99, Value: []byte{0xAA}}}}
	out, err := ea.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	ea2, err := DecodeEA(out)
	if err != nil {
		t.Fatalf("DecodeEA: %v", err)
	}
	if len(ea2.Parameters) != 1 || !bytes.Equal(ea2.Parameters[0].Value, []byte{0xAA}) {
		t.Errorf("Parameters = %v", ea2.Parameters)
	}
}

func TestEA_MarshalBinary_ParamValueTooLong(t *testing.T) {
	ea := &EA{Parameters: []Parameter{{Code: 0x99, Value: make([]byte, 256)}}}
	_, err := ea.MarshalBinary()
	if err == nil || !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Errorf("expected ErrUnexpectedParameterLength, got %v", err)
	}
}

func TestRJ_MarshalBinary_RoundTrip(t *testing.T) {
	rj, err := DecodeRJ(minimalRJ)
	if err != nil {
		t.Fatalf("DecodeRJ: %v", err)
	}
	out, err := rj.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(out, minimalRJ) {
		t.Errorf("round-trip: got %x want %x", out, minimalRJ)
	}
}

func TestDecode_ED_AK_EA_RJ(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
		typ  TPDUType
	}{
		{"ED", minimalED, TypeED},
		{"AK", minimalAK, TypeAK},
		{"EA", minimalEA, TypeEA},
		{"RJ", minimalRJ, TypeRJ},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Decode(tc.b)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			assertDecodedInvariant(t, d)
			if d.Type != tc.typ {
				t.Errorf("Type = %s, want %s", d.Type, tc.typ)
			}
		})
	}
}
