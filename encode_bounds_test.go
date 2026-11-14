// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"errors"
	"fmt"
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

// CDT is 4 bits of octet 2 and TPDU-NR 7 bits of its octet (X.224 13.3.3,
// 13.4.3, 13.7.3, 13.8.3, 13.9.3, 13.11.3). Every encoder writes a value
// that fits and decodes it back unchanged, and refuses one that does not fit
// with ErrMissingRequiredField.
func TestMarshal_CDTAndTPDUNRBounds(t *testing.T) {
	ref := uint16(0x1234)
	fields := []struct {
		name    string
		max     uint8
		marshal func(v uint8) ([]byte, error) // a TPDU carrying v in the field
	}{
		{"CR CDT", 15, func(v uint8) ([]byte, error) { return (&CR{CDT: v, SourceRef: 1}).MarshalBinary() }},
		{"CC CDT", 15, func(v uint8) ([]byte, error) { return (&CC{CDT: v, DestinationRef: 1, SourceRef: 2}).MarshalBinary() }},
		{"AK CDT", 15, func(v uint8) ([]byte, error) { return (&AK{CDT: v, DestinationRef: ref, YRTUNR: 3}).MarshalBinary() }},
		{"RJ CDT", 15, func(v uint8) ([]byte, error) { return (&RJ{CDT: v, DestinationRef: ref, YRTUNR: 3}).MarshalBinary() }},
		{"DT class 0 TPDU-NR", 127, func(v uint8) ([]byte, error) {
			return (&DT{EOT: true, TPDUNR: &v, UserData: []byte{1}}).MarshalBinary()
		}},
		{"DT normal TPDU-NR", 127, func(v uint8) ([]byte, error) {
			return (&DT{EOT: true, TPDUNR: &v, DestinationRef: &ref, UserData: []byte{1}}).MarshalBinary()
		}},
		{"ED TPDU-NR", 127, func(v uint8) ([]byte, error) {
			return (&ED{DestinationRef: &ref, TPDUNR: &v, EOT: true, UserData: []byte{1}}).MarshalBinary()
		}},
	}
	// field decodes b and returns the CDT or TPDU-NR it carries.
	field := func(b []byte) (uint8, error) {
		d, err := Decode(b)
		if err != nil {
			return 0, err
		}
		switch d.Type {
		case TypeCR:
			return d.CR.CDT, nil
		case TypeCC:
			return d.CC.CDT, nil
		case TypeAK:
			return d.AK.CDT, nil
		case TypeRJ:
			return d.RJ.CDT, nil
		case TypeDT:
			return *d.DT.TPDUNR, nil
		case TypeED:
			return *d.ED.TPDUNR, nil
		default:
			return 0, fmt.Errorf("%s carries neither CDT nor TPDU-NR", d.Type)
		}
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			for _, v := range []uint8{0, 1, f.max - 1, f.max} {
				b, err := f.marshal(v)
				if err != nil {
					t.Fatalf("%d: %v, want it encoded", v, err)
				}
				if got, err := field(b); err != nil || got != v {
					t.Fatalf("%d encoded as % x, decodes to %d, %v", v, b, got, err)
				}
			}
			for _, v := range []uint8{f.max + 1, f.max + 2, 128, 255} {
				if b, err := f.marshal(v); !errors.Is(err, ErrMissingRequiredField) {
					t.Fatalf("%d (field holds at most %d): % x, %v; want ErrMissingRequiredField", v, f.max, b, err)
				}
			}
		})
	}
}

// (*DT).MarshalBinary writes only what DecodeDT reads back as it was built:
// no variable part in the class 0 and 1 format (X.224 13.7.1 a), and an even
// LI in the normal format (an odd LI is the extended format, X.224 13.7.4
// NOTE). Anything else is refused with ErrUnsupportedDTVariant.
func TestMarshalDT_OnlyFormatsDecodeDTReadsBack(t *testing.T) {
	ref := uint16(0x1234)
	nr := uint8(5)
	// param returns one parameter whose encoding takes n octets (n >= 2).
	param := func(n int) Parameter { return Parameter{Code: 0x85, Value: make([]byte, n-2)} }

	t.Run("class 0 and 1 format", func(t *testing.T) {
		for _, params := range [][]Parameter{
			{param(2)},
			{param(3)},
			{param(4)},
			{param(2), param(2)},
			{{Code: 0x99, Value: make([]byte, 255)}}, // also too long: the format is checked first
		} {
			dt := &DT{EOT: true, Parameters: params, UserData: []byte{1}}
			if b, err := dt.MarshalBinary(); !errors.Is(err, ErrUnsupportedDTVariant) {
				t.Errorf("%d parameters without DestinationRef: % x, %v; want ErrUnsupportedDTVariant", len(params), b, err)
			}
		}
		// No parameter, nil or empty: LI 2.
		for _, params := range [][]Parameter{nil, {}} {
			b, err := (&DT{EOT: true, Parameters: params, UserData: []byte{1}}).MarshalBinary()
			if err != nil || b[0] != 2 {
				t.Errorf("Parameters %#v: % x, %v; want LI 2", params, b, err)
			}
		}
	})

	t.Run("normal format", func(t *testing.T) {
		// The variable part is n octets; LI = 4 + n, and MaxLI is 254.
		for _, n := range []int{0, 2, 3, 4, 5, 6, 7, 248, 249, 250, 251} {
			var params []Parameter
			if n > 0 {
				params = []Parameter{param(n)}
			}
			dt := &DT{EOT: true, TPDUNR: &nr, DestinationRef: &ref, Parameters: params, UserData: []byte{1, 2}}
			b, err := dt.MarshalBinary()
			li := 4 + n
			switch {
			case li > MaxLI:
				if !errors.Is(err, ErrInvalidLI) {
					t.Errorf("variable part of %d octets (LI %d): %v, want ErrInvalidLI", n, li, err)
				}
			case li%2 != 0:
				if !errors.Is(err, ErrUnsupportedDTVariant) {
					t.Errorf("variable part of %d octets (LI %d): % x, %v; want ErrUnsupportedDTVariant", n, li, b, err)
				}
			default:
				if err != nil {
					t.Fatalf("variable part of %d octets (LI %d): %v", n, li, err)
				}
				got, err := DecodeDT(b)
				if err != nil {
					t.Fatalf("variable part of %d octets: % x does not decode: %v", n, b, err)
				}
				if got.DestinationRef == nil || *got.DestinationRef != ref || *got.TPDUNR != nr ||
					len(got.Parameters) != len(params) || !bytes.Equal(got.UserData, dt.UserData) {
					t.Fatalf("variable part of %d octets: decoded %+v, built %+v", n, got, dt)
				}
			}
		}
	})
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
// The DT encoder refuses a variable part of odd length, which would make LI
// odd (the extended format, X.224 13.7.4 NOTE), so every TPDU an encoder
// writes decodes.
func FuzzMarshalParameters(f *testing.F) {
	f.Add(uint8(0), uint8(0x85), uint16(3), uint8(1), []byte("abc"))
	f.Add(uint8(3), uint8(0xC1), uint16(255), uint8(1), []byte{})
	f.Add(uint8(3), uint8(0xC1), uint16(1), uint8(1), []byte{0x01}) // DT, variable part of 3 octets
	f.Add(uint8(3), uint8(0xC1), uint16(0), uint8(2), []byte{})     // DT, variable part of 5 octets
	f.Add(uint8(3), uint8(0x85), uint16(2), uint8(1), []byte{0x02}) // DT, variable part of 4 octets
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
		varLen := 0
		for _, p := range params {
			varLen += 2 + len(p.Value)
		}
		typ, b, err := marshalWithParams(kind, params)
		if err != nil {
			switch {
			case errors.Is(err, ErrUnexpectedParameterLength), errors.Is(err, ErrInvalidLI):
			case typ == TypeDT && errors.Is(err, ErrUnsupportedDTVariant):
				if varLen%2 == 0 {
					t.Fatalf("DT with a variable part of %d octets refused: %v", varLen, err)
				}
			default:
				t.Fatalf("%v: unclassified marshal error: %v", typ, err)
			}
			return
		}
		if typ == TypeDT && varLen%2 != 0 {
			t.Fatalf("DT with a variable part of %d octets written with LI %d", varLen, b[0])
		}
		if b[0] > MaxLI || int(b[0])+1 > len(b) {
			t.Fatalf("%v: LI %d over %d-octet TPDU", typ, b[0], len(b))
		}
		d, err := Decode(b)
		if err != nil {
			t.Fatalf("%v: marshalled TPDU % x does not decode: %v", typ, b, err)
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
