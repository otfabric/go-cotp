// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestPreferredMaxTPDULength(t *testing.T) {
	t.Run("units_1", func(t *testing.T) {
		got, err := PreferredMaxTPDULength(1)
		if err != nil || got != 128 {
			t.Fatalf("got %d,%v want 128,nil", got, err)
		}
	})
	t.Run("units_511", func(t *testing.T) {
		got, err := PreferredMaxTPDULength(511)
		if err != nil || got != 65408 {
			t.Fatalf("got %d,%v want 65408,nil", got, err)
		}
	})
	t.Run("units_above_511_accepted", func(t *testing.T) {
		got, err := PreferredMaxTPDULength(512)
		if err != nil || got != 65536 {
			t.Fatalf("got %d,%v want 65536,nil", got, err)
		}
	})
	t.Run("units_zero_error", func(t *testing.T) {
		_, err := PreferredMaxTPDULength(0)
		if !errors.Is(err, ErrUnexpectedParameterLength) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("max_uint32_portable", func(t *testing.T) {
		got, err := PreferredMaxTPDULength(math.MaxUint32)
		if err != nil {
			t.Fatal(err)
		}
		want := uint64(math.MaxUint32) * 128
		if got != want {
			t.Fatalf("got %d want %d", got, want)
		}
	})
}

func TestPreferredMaxTPDUUnits(t *testing.T) {
	t.Run("exact_128", func(t *testing.T) {
		u, err := PreferredMaxTPDUUnits(128)
		if err != nil || u != 1 {
			t.Fatalf("got %d,%v", u, err)
		}
	})
	t.Run("not_multiple", func(t *testing.T) {
		_, err := PreferredMaxTPDUUnits(1000)
		if !errors.Is(err, ErrUnexpectedParameterLength) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("zero", func(t *testing.T) {
		_, err := PreferredMaxTPDUUnits(0)
		if !errors.Is(err, ErrUnexpectedParameterLength) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestDecodePreferredMaxUnits(t *testing.T) {
	tests := []struct {
		name    string
		value   []byte
		want    uint32
		wantErr bool
	}{
		{"F0_01_01", []byte{0x01}, 1, false},
		{"leading_zero_2", []byte{0x00, 0x01}, 1, false},
		{"units_511", []byte{0x00, 0x00, 0x01, 0xFF}, 511, false},
		{"zero_length", []byte{}, 0, true},
		{"len_5", []byte{0, 0, 0, 0, 1}, 0, true},
		{"all_zero", []byte{0x00}, 0, true},
		{"above_511", []byte{0x02, 0x00}, 512, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodePreferredMaxUnits(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %d,%v want %d", got, err, tt.want)
			}
		})
	}
}

func TestEncodePreferredMaxUnitsCanonical(t *testing.T) {
	enc, err := encodePreferredMaxUnits(1)
	if err != nil || !bytes.Equal(enc, []byte{0x01}) {
		t.Fatalf("got %v,%v", enc, err)
	}
	// Leading-zero decode then canonical re-encode.
	units, err := decodePreferredMaxUnits([]byte{0x00, 0x01})
	if err != nil || units != 1 {
		t.Fatal(err)
	}
	enc, err = encodePreferredMaxUnits(units)
	if err != nil || !bytes.Equal(enc, []byte{0x01}) {
		t.Fatalf("re-encode %v", enc)
	}
}

func TestCRCCPreferredMaxRoundTrip(t *testing.T) {
	units := uint32(8)
	cr := &CR{
		SourceRef:            1,
		PreferredMaxTPDUSize: &units,
		TPDUSize:             bytePtr(0x0A),
	}
	raw, err := cr.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCR(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.PreferredMaxTPDUSize == nil || *got.PreferredMaxTPDUSize != 8 {
		t.Fatalf("preferred=%v", got.PreferredMaxTPDUSize)
	}
	if got.TPDUSize == nil || *got.TPDUSize != 0x0A {
		t.Fatalf("size=%v", got.TPDUSize)
	}

	cc := &CC{SourceRef: 2, DestinationRef: 1, PreferredMaxTPDUSize: &units}
	raw, err = cc.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	gotCC, err := DecodeCC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if gotCC.PreferredMaxTPDUSize == nil || *gotCC.PreferredMaxTPDUSize != 8 {
		t.Fatalf("cc preferred=%v", gotCC.PreferredMaxTPDUSize)
	}
}

func TestDuplicatePreferredMaxLastWins(t *testing.T) {
	// 0xF0 units 1 then units 8
	b := []byte{0xF0, 1, 0x01, 0xF0, 1, 0x08}
	r, err := parseCRCCVariablePart(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.preferredMaxTPDUSize == nil || *r.preferredMaxTPDUSize != 8 {
		t.Fatalf("got %v", r.preferredMaxTPDUSize)
	}
}

func FuzzDecodePreferredMaxUnits(f *testing.F) {
	f.Add([]byte{0x01})
	f.Add([]byte{0x00, 0x01})
	f.Add([]byte{0x00, 0x00, 0x01, 0xFF})
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{1, 2, 3, 4, 5})
	f.Fuzz(func(t *testing.T, data []byte) {
		units, err := decodePreferredMaxUnits(data)
		if err != nil {
			return
		}
		if units == 0 {
			t.Fatal("successful decode produced zero units")
		}
		enc, err := encodePreferredMaxUnits(units)
		if err != nil {
			t.Fatal(err)
		}
		if len(enc) < 1 || len(enc) > 4 {
			t.Fatalf("bad encode len %d", len(enc))
		}
	})
}
