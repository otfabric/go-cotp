// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"testing"
)

func TestParseCRCCVariablePart(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, r *crccVariableResult)
	}{
		{
			name:    "empty",
			b:       []byte{},
			wantErr: nil,
			check: func(t *testing.T, r *crccVariableResult) {
				if r.callingSelector != nil || r.calledSelector != nil || r.tpduSize != nil || r.preferredMaxTPDUSize != nil || len(r.parameters) != 0 {
					t.Errorf("expected empty result")
				}
			},
		},
		{
			name:    "single known 0xC1",
			b:       []byte{0xC1, 2, 0x01, 0x02},
			wantErr: nil,
			check: func(t *testing.T, r *crccVariableResult) {
				if len(r.callingSelector) != 2 || r.callingSelector[0] != 0x01 || r.callingSelector[1] != 0x02 {
					t.Errorf("callingSelector = %v", r.callingSelector)
				}
				if len(r.parameters) != 0 {
					t.Errorf("parameters = %v", r.parameters)
				}
			},
		},
		{
			name:    "0xC0 TPDU size",
			b:       []byte{0xC0, 1, 0x07},
			wantErr: nil,
			check: func(t *testing.T, r *crccVariableResult) {
				if r.tpduSize == nil || *r.tpduSize != 0x07 {
					t.Errorf("tpduSize = %v", r.tpduSize)
				}
			},
		},
		{
			name:    "known + unknown",
			b:       []byte{0xC1, 1, 0xAA, 0xFF, 2, 0xBB, 0xCC},
			wantErr: nil,
			check: func(t *testing.T, r *crccVariableResult) {
				if len(r.callingSelector) != 1 || r.callingSelector[0] != 0xAA {
					t.Errorf("callingSelector = %v", r.callingSelector)
				}
				if len(r.parameters) != 1 || r.parameters[0].Code != 0xFF || len(r.parameters[0].Value) != 2 {
					t.Errorf("parameters = %v", r.parameters)
				}
			},
		},
		{
			name:    "duplicate 0xC1 last wins",
			b:       []byte{0xC1, 1, 0x01, 0xC1, 1, 0x02},
			wantErr: nil,
			check: func(t *testing.T, r *crccVariableResult) {
				if len(r.callingSelector) != 1 || r.callingSelector[0] != 0x02 {
					t.Errorf("callingSelector = %v, want [0x02]", r.callingSelector)
				}
			},
		},
		{
			name:    "truncated after code+length",
			b:       []byte{0xC1, 3, 0x01},
			wantErr: ErrMalformedParameter,
		},
		{
			name:    "0xC0 wrong length",
			b:       []byte{0xC0, 2, 0x07, 0x08},
			wantErr: ErrUnexpectedParameterLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := parseCRCCVariablePart(tt.b)
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
				tt.check(t, r)
			}
		})
	}
}

func TestParseVariablePart(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
		check   func(t *testing.T, params []Parameter)
	}{
		{
			name:    "empty",
			b:       []byte{},
			wantErr: nil,
			check: func(t *testing.T, params []Parameter) {
				if len(params) != 0 {
					t.Errorf("params = %v", params)
				}
			},
		},
		{
			name:    "single param",
			b:       []byte{0x99, 2, 0xAA, 0xBB},
			wantErr: nil,
			check: func(t *testing.T, params []Parameter) {
				if len(params) != 1 || params[0].Code != 0x99 || len(params[0].Value) != 2 || params[0].Value[0] != 0xAA {
					t.Errorf("params = %v", params)
				}
			},
		},
		{
			name:    "two params",
			b:       []byte{0x01, 1, 0x11, 0x02, 2, 0x22, 0x33},
			wantErr: nil,
			check: func(t *testing.T, params []Parameter) {
				if len(params) != 2 || params[0].Code != 0x01 || params[1].Code != 0x02 {
					t.Errorf("params = %v", params)
				}
			},
		},
		{
			name:    "truncated",
			b:       []byte{0x01, 3, 0x01},
			wantErr: ErrMalformedParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := parseVariablePart(tt.b)
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
				tt.check(t, params)
			}
		})
	}
}

func FuzzParseVariablePart(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x99, 2, 0xAA, 0xBB})
	f.Add([]byte{0xC1, 0, 0xC2, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseVariablePart(data)
	})
}

func FuzzParseCRCCVariablePart(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xC1, 2, 0x01, 0x02})
	f.Add([]byte{0xC0, 1, 7})
	f.Add([]byte{0xF0, 1, 0x01})
	f.Add([]byte{0xF0, 2, 0x00, 0x01})
	f.Add([]byte{0xF0, 4, 0x00, 0x00, 0x01, 0xFF})
	f.Add([]byte{0xF0, 0})
	f.Add([]byte{0xF0, 5, 1, 2, 3, 4, 5})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseCRCCVariablePart(data)
	})
}
