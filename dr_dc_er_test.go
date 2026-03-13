package cotp

import (
	"bytes"
	"errors"
	"testing"
)

var (
	minimalDR = []byte{0x06, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00} // LI=6, code, DST=1, SRC=2, reason=0
	minimalDC = []byte{0x05, 0xC0, 0x00, 0x01, 0x00, 0x02}       // LI=5, code, DST=1, SRC=2
	minimalER = []byte{0x04, 0x70, 0x00, 0x01, 0x02}             // LI=4, code, DST=1, reject=2
)

func TestDecodeDR(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, dr *DR)
	}{
		{
			name:    "minimal",
			b:       minimalDR,
			wantErr: nil,
			check: func(t *testing.T, dr *DR) {
				if dr.DestinationRef != 1 || dr.SourceRef != 2 || dr.Reason != 0 {
					t.Errorf("DST=%d SRC=%d Reason=%d", dr.DestinationRef, dr.SourceRef, dr.Reason)
				}
				if len(dr.Parameters) != 0 || len(dr.UserData) != 0 {
					t.Errorf("Params=%v UserData=%v", dr.Parameters, dr.UserData)
				}
			},
		},
		{
			name:    "with user data",
			b:       []byte{0x06, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0xDE, 0xAD},
			wantErr: nil,
			check: func(t *testing.T, dr *DR) {
				if !bytes.Equal(dr.UserData, []byte{0xDE, 0xAD}) {
					t.Errorf("UserData = %v", dr.UserData)
				}
			},
		},
		{
			name:    "too short",
			b:       []byte{0x06, 0x80, 0x00},
			wantErr: ErrTooShort,
		},
		{
			name:    "wrong type",
			b:       []byte{0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: ErrInvalidTPDUCode,
		},
		{
			name:    "with variable part",
			b:       []byte{0x0a, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x99, 0x02, 0xAA, 0xBB}, // LI=10: fixed 6 + param 4
			wantErr: nil,
			check: func(t *testing.T, dr *DR) {
				if len(dr.Parameters) != 1 || dr.Parameters[0].Code != 0x99 || !bytes.Equal(dr.Parameters[0].Value, []byte{0xAA, 0xBB}) {
					t.Errorf("Parameters = %v", dr.Parameters)
				}
			},
		},
		{
			name:    "header length exceeds buffer",
			b:       []byte{0x0a, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00}, // LI=10 but only 7 bytes
			wantErr: ErrTooShort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dr, err := DecodeDR(tt.b)
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
				tt.check(t, dr)
			}
		})
	}
}

func TestDecodeDC(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, dc *DC)
	}{
		{
			name:    "minimal",
			b:       minimalDC,
			wantErr: nil,
			check: func(t *testing.T, dc *DC) {
				if dc.DestinationRef != 1 || dc.SourceRef != 2 {
					t.Errorf("DST=%d SRC=%d", dc.DestinationRef, dc.SourceRef)
				}
			},
		},
		{
			name:    "too short",
			b:       []byte{0x05, 0xC0},
			wantErr: ErrTooShort,
		},
		{
			name:    "wrong type",
			b:       []byte{0x05, 0x80, 0x00, 0x01, 0x00, 0x02},
			wantErr: ErrInvalidTPDUCode,
		},
		{
			name:    "with variable part",
			b:       []byte{0x09, 0xC0, 0x00, 0x01, 0x00, 0x02, 0x99, 0x02, 0xAA, 0xBB}, // LI=9: fixed 5 + param 4
			wantErr: nil,
			check: func(t *testing.T, dc *DC) {
				if len(dc.Parameters) != 1 || dc.Parameters[0].Code != 0x99 {
					t.Errorf("Parameters = %v", dc.Parameters)
				}
			},
		},
		{
			name:    "header length exceeds buffer",
			b:       []byte{0x0a, 0xC0, 0x00, 0x01, 0x00, 0x02}, // LI=10 but only 6 bytes
			wantErr: ErrTooShort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc, err := DecodeDC(tt.b)
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
				tt.check(t, dc)
			}
		})
	}
}

func TestDecodeER(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, er *ER)
	}{
		{
			name:    "minimal",
			b:       minimalER,
			wantErr: nil,
			check: func(t *testing.T, er *ER) {
				if er.DestinationRef != 1 || er.RejectCause != 2 {
					t.Errorf("DST=%d Cause=%d", er.DestinationRef, er.RejectCause)
				}
			},
		},
		{
			name:    "too short",
			b:       []byte{0x04, 0x70},
			wantErr: ErrTooShort,
		},
		{
			name:    "wrong type",
			b:       []byte{0x04, 0x80, 0x00, 0x01, 0x02},
			wantErr: ErrInvalidTPDUCode,
		},
		{
			name:    "with variable part",
			b:       []byte{0x08, 0x70, 0x00, 0x01, 0x02, 0x99, 0x02, 0xAA, 0xBB}, // LI=8: fixed 4 + param 4
			wantErr: nil,
			check: func(t *testing.T, er *ER) {
				if len(er.Parameters) != 1 || er.Parameters[0].Code != 0x99 {
					t.Errorf("Parameters = %v", er.Parameters)
				}
			},
		},
		{
			name:    "header length exceeds buffer",
			b:       []byte{0x08, 0x70, 0x00, 0x01, 0x02}, // LI=8 but only 5 bytes
			wantErr: ErrTooShort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			er, err := DecodeER(tt.b)
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
				tt.check(t, er)
			}
		})
	}
}

func TestDecode_DR_DC_ER(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
		typ  TPDUType
	}{
		{"DR", minimalDR, TypeDR},
		{"DC", minimalDC, TypeDC},
		{"ER", minimalER, TypeER},
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

func TestDR_MarshalBinary_RoundTrip(t *testing.T) {
	dr, err := DecodeDR(minimalDR)
	if err != nil {
		t.Fatalf("DecodeDR: %v", err)
	}
	out, err := dr.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(out, minimalDR) {
		t.Errorf("round-trip: got %x want %x", out, minimalDR)
	}
}

func TestDC_MarshalBinary_RoundTrip(t *testing.T) {
	dc, err := DecodeDC(minimalDC)
	if err != nil {
		t.Fatalf("DecodeDC: %v", err)
	}
	out, err := dc.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(out, minimalDC) {
		t.Errorf("round-trip: got %x want %x", out, minimalDC)
	}
}

func TestER_MarshalBinary_RoundTrip(t *testing.T) {
	er, err := DecodeER(minimalER)
	if err != nil {
		t.Fatalf("DecodeER: %v", err)
	}
	out, err := er.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(out, minimalER) {
		t.Errorf("round-trip: got %x want %x", out, minimalER)
	}
}

func TestDR_MarshalBinary_WithParams(t *testing.T) {
	dr := &DR{DestinationRef: 1, SourceRef: 2, Reason: 0, Parameters: []Parameter{{Code: 0x99, Value: []byte{0xAA, 0xBB}}}}
	out, err := dr.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	dr2, err := DecodeDR(out)
	if err != nil {
		t.Fatalf("DecodeDR: %v", err)
	}
	if len(dr2.Parameters) != 1 || !bytes.Equal(dr2.Parameters[0].Value, []byte{0xAA, 0xBB}) {
		t.Errorf("Parameters = %v", dr2.Parameters)
	}
}

func TestDC_MarshalBinary_WithParams(t *testing.T) {
	dc := &DC{DestinationRef: 1, SourceRef: 2, Parameters: []Parameter{{Code: 0x99, Value: []byte{0x01}}}}
	out, err := dc.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	dc2, err := DecodeDC(out)
	if err != nil {
		t.Fatalf("DecodeDC: %v", err)
	}
	if len(dc2.Parameters) != 1 {
		t.Errorf("Parameters = %v", dc2.Parameters)
	}
}

func TestER_MarshalBinary_WithParams(t *testing.T) {
	er := &ER{DestinationRef: 1, RejectCause: 2, Parameters: []Parameter{{Code: 0x99, Value: []byte{0x01}}}}
	out, err := er.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	er2, err := DecodeER(out)
	if err != nil {
		t.Fatalf("DecodeER: %v", err)
	}
	if len(er2.Parameters) != 1 {
		t.Errorf("Parameters = %v", er2.Parameters)
	}
}

func TestDR_MarshalBinary_ParamValueTooLong(t *testing.T) {
	dr := &DR{Parameters: []Parameter{{Code: 0x99, Value: make([]byte, 256)}}}
	_, err := dr.MarshalBinary()
	if err == nil || !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Errorf("expected ErrUnexpectedParameterLength, got %v", err)
	}
}

func TestDC_MarshalBinary_ParamValueTooLong(t *testing.T) {
	dc := &DC{Parameters: []Parameter{{Code: 0x99, Value: make([]byte, 256)}}}
	_, err := dc.MarshalBinary()
	if err == nil || !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Errorf("expected ErrUnexpectedParameterLength, got %v", err)
	}
}

func TestER_MarshalBinary_ParamValueTooLong(t *testing.T) {
	er := &ER{Parameters: []Parameter{{Code: 0x99, Value: make([]byte, 256)}}}
	_, err := er.MarshalBinary()
	if err == nil || !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Errorf("expected ErrUnexpectedParameterLength, got %v", err)
	}
}
