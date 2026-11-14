// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"testing"
)

// marshalWithParams builds a TPDU of the given kind carrying params and
// marshals it. kind selects one of the seven TPDUs with a generic variable
// part; it returns the TPDU type it built.
func marshalWithParams(kind uint8, params []Parameter) (TPDUType, []byte, error) {
	ref := uint16(0x1234)
	nr := uint8(5)
	switch kind % 7 {
	case 0:
		b, err := (&AK{CDT: 1, DestinationRef: ref, YRTUNR: 3, Parameters: params}).MarshalBinary()
		return TypeAK, b, err
	case 1:
		b, err := (&DC{DestinationRef: ref, SourceRef: 2, Parameters: params}).MarshalBinary()
		return TypeDC, b, err
	case 2:
		b, err := (&DR{DestinationRef: ref, SourceRef: 2, Reason: 1, Parameters: params, UserData: []byte{9}}).MarshalBinary()
		return TypeDR, b, err
	case 3:
		b, err := (&DT{EOT: true, TPDUNR: &nr, DestinationRef: &ref, Parameters: params, UserData: []byte{1, 2}}).MarshalBinary()
		return TypeDT, b, err
	case 4:
		b, err := (&EA{DestinationRef: ref, YREDTUNR: 4, Parameters: params}).MarshalBinary()
		return TypeEA, b, err
	case 5:
		b, err := (&ED{DestinationRef: &ref, TPDUNR: &nr, Parameters: params, UserData: []byte{7}}).MarshalBinary()
		return TypeED, b, err
	default:
		b, err := (&ER{DestinationRef: ref, RejectCause: 2, Parameters: params}).MarshalBinary()
		return TypeER, b, err
	}
}

func decodedParams(d Decoded) []Parameter {
	switch d.Type {
	case TypeAK:
		return d.AK.Parameters
	case TypeDC:
		return d.DC.Parameters
	case TypeDR:
		return d.DR.Parameters
	case TypeDT:
		return d.DT.Parameters
	case TypeEA:
		return d.EA.Parameters
	case TypeED:
		return d.ED.Parameters
	case TypeER:
		return d.ER.Parameters
	case TypeCR, TypeCC, TypeRJ:
		return nil
	}
	return nil
}

// A parameter value longer than the one-octet length field is rejected by
// every encoder instead of being written with a wrapped length.
func TestMarshal_ParameterValueLengthBound(t *testing.T) {
	for kind := range uint8(7) {
		for _, n := range []int{256, 257, 511, 65536} {
			typ, b, err := marshalWithParams(kind, []Parameter{{Code: 0x99, Value: make([]byte, n)}})
			if !errors.Is(err, ErrUnexpectedParameterLength) {
				t.Errorf("%v value length %d: err = %v, out %d octets; want ErrUnexpectedParameterLength", typ, n, err, len(b))
			}
		}
		// 255 fits the length field but not the header (MaxLI 254).
		typ, _, err := marshalWithParams(kind, []Parameter{{Code: 0x99, Value: make([]byte, 255)}})
		if !errors.Is(err, ErrInvalidLI) {
			t.Errorf("%v value length 255: err = %v, want ErrInvalidLI", typ, err)
		}
	}
}

func TestMarshal_CRCCSelectorLengthBound(t *testing.T) {
	long := make([]byte, 256)
	for _, v := range []interface{ MarshalBinary() ([]byte, error) }{
		&CR{SourceRef: 1, CallingSelector: long},
		&CR{SourceRef: 1, CalledSelector: long},
		&CR{SourceRef: 1, Parameters: []Parameter{{Code: 0x85, Value: long}}},
		&CC{SourceRef: 1, CallingSelector: long},
		&CC{SourceRef: 1, CalledSelector: long},
		&CC{SourceRef: 1, Parameters: []Parameter{{Code: 0x85, Value: long}}},
	} {
		if _, err := v.MarshalBinary(); !errors.Is(err, ErrUnexpectedParameterLength) {
			t.Errorf("%T: err = %v, want ErrUnexpectedParameterLength", v, err)
		}
	}
}

func TestEncodePreferredMaxUnits_Boundaries(t *testing.T) {
	cases := []struct {
		units uint32
		want  []byte
	}{
		{1, []byte{0x01}},
		{0xFF, []byte{0xFF}},
		{0x100, []byte{0x01, 0x00}},
		{0xFFFF, []byte{0xFF, 0xFF}},
		{0x10000, []byte{0x01, 0x00, 0x00}},
		{0xFFFFFF, []byte{0xFF, 0xFF, 0xFF}},
		{0x1000000, []byte{0x01, 0x00, 0x00, 0x00}},
		{math.MaxUint32, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, tc := range cases {
		got, err := encodePreferredMaxUnits(tc.units)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("encode(%#x) = %x, %v; want %x", tc.units, got, err, tc.want)
		}
	}
	if _, err := encodePreferredMaxUnits(0); !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Errorf("encode(0): %v", err)
	}
}

// Ceilings and peer offers far above the ITOT maximum never wrap into a small
// unit count: the selection is either capped at 511 units or rejected.
func TestSelectPreferredPath_LargeInputs(t *testing.T) {
	huge := []int{MaxPreferredUnitsITOT*128 + 128, MaxITOTTPDULength, math.MaxInt32, math.MaxInt}
	if strconv.IntSize > 32 {
		// One above the 32-bit boundary. Built at run time, so the test
		// package also compiles where int has 32 bits.
		over := math.MaxInt32
		huge = append(huge, over+1)
	}
	for _, peer := range huge {
		for _, srv := range huge {
			for _, cb := range append([]int{0}, huge...) {
				sel, err := selectPreferredPath(peer, srv, cb)
				if err != nil {
					continue
				}
				if sel.PreferredUnits == nil || *sel.PreferredUnits == 0 || *sel.PreferredUnits > MaxPreferredUnitsITOT {
					t.Fatalf("peer %d srv %d cb %d: units %v", peer, srv, cb, sel.PreferredUnits)
				}
				if sel.Effective != int(*sel.PreferredUnits)*128 {
					t.Fatalf("peer %d srv %d cb %d: effective %d != units*128", peer, srv, cb, sel.Effective)
				}
			}
		}
	}
}

func FuzzEncodePreferredMaxUnits(f *testing.F) {
	for _, u := range []uint32{0, 1, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFF, 0x1000000, math.MaxUint32} {
		f.Add(u)
	}
	f.Fuzz(func(t *testing.T, units uint32) {
		enc, err := encodePreferredMaxUnits(units)
		if units == 0 {
			if err == nil {
				t.Fatal("zero units encoded")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(enc) < 1 || len(enc) > 4 || enc[0] == 0 {
			t.Fatalf("encode(%#x) = %x: not minimal", units, enc)
		}
		got, err := decodePreferredMaxUnits(enc)
		if err != nil || got != units {
			t.Fatalf("decode(encode(%#x)) = %#x, %v", units, got, err)
		}
	})
}

// FuzzMarshalParameters drives the encoders with fuzz-chosen parameters,
// including values longer than the length field: marshal either fails with a
// classified error or produces a TPDU that decodes to the same parameters.
func FuzzMarshalParameters(f *testing.F) {
	f.Add(uint8(0), uint8(0x85), uint16(3), uint8(1), []byte("abc"))
	f.Add(uint8(3), uint8(0xC1), uint16(255), uint8(1), []byte{})
	f.Add(uint8(5), uint8(0x99), uint16(256), uint8(2), []byte{0xFF})
	f.Add(uint8(6), uint8(0x00), uint16(0), uint8(40), []byte{})
	f.Fuzz(func(t *testing.T, kind, code uint8, valueLen uint16, count uint8, seed []byte) {
		params := make([]Parameter, 0, count%64)
		for i := 0; i < int(count%64); i++ {
			v := make([]byte, int(valueLen)+i)
			for j := range v {
				if len(seed) > 0 {
					v[j] = seed[j%len(seed)]
				}
			}
			params = append(params, Parameter{Code: code + uint8(i), Value: v})
		}
		typ, b, err := marshalWithParams(kind, params)
		if err != nil {
			if !errors.Is(err, ErrUnexpectedParameterLength) && !errors.Is(err, ErrInvalidLI) {
				t.Fatalf("%v: unclassified marshal error: %v", typ, err)
			}
			return
		}
		if b[0] > MaxLI || int(b[0])+1 > len(b) {
			t.Fatalf("%v: LI %d over %d-octet TPDU", typ, b[0], len(b))
		}
		d, err := Decode(b)
		if err != nil {
			// The decoder may refuse a parameter code the encoder passes
			// through; it must not refuse the framing.
			if errors.Is(err, ErrInvalidLI) || errors.Is(err, ErrLengthMismatch) || errors.Is(err, ErrTooShort) {
				t.Fatalf("%v: marshalled TPDU has bad framing: %v", typ, err)
			}
			return
		}
		if d.Type != typ {
			t.Fatalf("type %v, want %v", d.Type, typ)
		}
		got := decodedParams(d)
		if len(got) != len(params) {
			t.Fatalf("%v: %d parameters decoded, %d marshalled", typ, len(got), len(params))
		}
		for i := range params {
			if got[i].Code != params[i].Code || !bytes.Equal(got[i].Value, params[i].Value) {
				t.Fatalf("%v: parameter %d changed in round trip", typ, i)
			}
		}
	})
}
