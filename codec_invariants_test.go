// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// decodeSentinels are the errors ERRORS.md documents for the decoders. Every
// decode failure matches one of them.
var decodeSentinels = []error{
	ErrTooShort,
	ErrInvalidLI,
	ErrLengthMismatch,
	ErrInvalidTPDUCode,
	ErrReservedTPDU,
	ErrMalformedParameter,
	ErrUnexpectedParameterLength,
	ErrUnsupportedTPDU,
	ErrUnsupportedDTVariant,
	ErrInvalidEDUserDataLength,
}

func assertDecodeSentinel(t *testing.T, err error) {
	t.Helper()
	for _, s := range decodeSentinels {
		if errors.Is(err, s) {
			return
		}
	}
	t.Fatalf("decode error matches no documented sentinel: %v", err)
}

// decodedSlices returns every byte slice a decoded TPDU exposes, by name.
func decodedSlices(d Decoded) map[string][]byte {
	out := map[string][]byte{}
	params := func(ps []Parameter) {
		for i, p := range ps {
			out[fmt.Sprintf("Parameters[%d].Value", i)] = p.Value
		}
	}
	switch d.Type {
	case TypeCR:
		out["CallingSelector"], out["CalledSelector"], out["UserData"] = d.CR.CallingSelector, d.CR.CalledSelector, d.CR.UserData
		params(d.CR.Parameters)
	case TypeCC:
		out["CallingSelector"], out["CalledSelector"], out["UserData"] = d.CC.CallingSelector, d.CC.CalledSelector, d.CC.UserData
		params(d.CC.Parameters)
	case TypeDT:
		out["UserData"] = d.DT.UserData
		params(d.DT.Parameters)
	case TypeDR:
		out["UserData"] = d.DR.UserData
		params(d.DR.Parameters)
	case TypeDC:
		params(d.DC.Parameters)
	case TypeER:
		params(d.ER.Parameters)
	case TypeED:
		out["UserData"] = d.ED.UserData
		params(d.ED.Parameters)
	case TypeAK:
		params(d.AK.Parameters)
	case TypeEA:
		params(d.EA.Parameters)
	case TypeRJ:
	}
	return out
}

// insideInput reports whether s is a sub-slice of input: the borrowing the
// package documents. An empty s holds no octet and is inside by definition.
func insideInput(s, input []byte) bool {
	if len(s) == 0 {
		return true
	}
	for i := range input {
		if &input[i] == &s[0] {
			return len(s) <= len(input)-i
		}
	}
	return false
}

// assertBorrowed checks the ownership contract of decoded slices: each one
// lies inside the input and has no capacity beyond its own octets.
func assertBorrowed(t *testing.T, d Decoded, input []byte) {
	t.Helper()
	for name, s := range decodedSlices(d) {
		if !insideInput(s, input) {
			t.Fatalf("%s %s is not a sub-slice of the input", d.Type, name)
		}
		if cap(s) != len(s) {
			t.Fatalf("%s %s has capacity %d beyond its length %d", d.Type, name, cap(s), len(s))
		}
	}
}

func marshalDecoded(d Decoded) ([]byte, error) {
	switch d.Type {
	case TypeCR:
		return d.CR.MarshalBinary()
	case TypeCC:
		return d.CC.MarshalBinary()
	case TypeDT:
		return d.DT.MarshalBinary()
	case TypeDR:
		return d.DR.MarshalBinary()
	case TypeDC:
		return d.DC.MarshalBinary()
	case TypeER:
		return d.ER.MarshalBinary()
	case TypeED:
		return d.ED.MarshalBinary()
	case TypeAK:
		return d.AK.MarshalBinary()
	case TypeEA:
		return d.EA.MarshalBinary()
	case TypeRJ:
		return d.RJ.MarshalBinary()
	}
	return nil, errors.New("no TPDU in Decoded")
}

// canonicalOctets returns the octets the encoder must write back for input,
// for the TPDU types whose encoding has one form, and false for CR and CC
// (parameter order, duplicates and the preferred-maximum length are
// normalised on encode).
//
// DT: the whole input, with the ROA bit cleared (the encoder does not model
// it, COMPLIANCE.md C-DT). DR, ED, and DC, ER, AK, EA and RJ, which have no
// data field and are refused with octets after their header: the whole
// input.
func canonicalOctets(typ TPDUType, input []byte) ([]byte, bool) {
	switch typ {
	case TypeDT:
		want := bytes.Clone(input)
		want[1] = 0xF0
		return want, true
	case TypeDR, TypeED, TypeDC, TypeER, TypeAK, TypeEA, TypeRJ:
		return input, true
	case TypeCR, TypeCC:
	}
	return nil, false
}

// assertDecodeInvariants is the oracle of the decoder fuzz targets and of the
// truncation table. For one input and the result of one decoder it checks:
//
//   - a failure matches a documented sentinel and returns no value;
//   - a success exposes only borrowed, clipped slices of the input;
//   - the value encodes, and decodes again to a deeply equal value;
//   - for the types with one encoding, the encoder writes back the octets
//     that were read;
//   - Decode, the generic entry point, returns the same value.
func assertDecodeInvariants(t *testing.T, input []byte, d Decoded, err error) {
	t.Helper()
	if err != nil {
		assertDecodeSentinel(t, err)
		if !reflect.DeepEqual(d, Decoded{}) {
			t.Fatalf("decode failed (%v) and returned a value: %+v", err, d)
		}
		return
	}
	assertDecodedInvariant(t, d)
	assertBorrowed(t, d, input)

	out, err := marshalDecoded(d)
	if err != nil {
		t.Fatalf("%s decoded from % x does not encode: %v", d.Type, input, err)
	}
	if want, ok := canonicalOctets(d.Type, input); ok && !bytes.Equal(out, want) {
		t.Fatalf("%s re-encoded as % x, want % x", d.Type, out, want)
	}
	if d.Type == TypeCR || d.Type == TypeCC {
		// The variable part is normalised on encode; the fixed part (code
		// and CDT, DST-REF, SRC-REF, class and options) has one encoding.
		if !bytes.Equal(out[1:7], input[1:7]) {
			t.Fatalf("%s fixed part re-encoded as % x, want % x", d.Type, out[1:7], input[1:7])
		}
	}
	again, err := Decode(out)
	if err != nil {
		t.Fatalf("%s re-encoded as % x does not decode: %v", d.Type, out, err)
	}
	if !reflect.DeepEqual(d, again) {
		t.Fatalf("%s round trip changed the value:\n first  %s\n second %s", d.Type, describe(d), describe(again))
	}
	generic, err := Decode(input)
	if err != nil || !reflect.DeepEqual(d, generic) {
		t.Fatalf("Decode disagrees with the %s decoder: %s, %v", d.Type, describe(generic), err)
	}

	switch d.Type {
	case TypeCR:
		if len(input) > MaxCRTPDULength {
			t.Fatalf("CR of %d octets accepted, limit %d", len(input), MaxCRTPDULength)
		}
	case TypeDT:
		// X.224 §13.7.4 NOTE: an even LI is the normal format, an odd LI
		// the extended one, which this codec does not decode.
		li := input[0]
		if li != 2 && (li < 4 || li%2 != 0) {
			t.Fatalf("DT with LI %d accepted", li)
		}
		if (li == 2) != (d.DT.DestinationRef == nil) {
			t.Fatalf("DT with LI %d: DestinationRef present = %v", li, d.DT.DestinationRef != nil)
		}
	case TypeED:
		if n := len(d.ED.UserData); n < MinEDUserDataLen || n > MaxEDUserDataLen {
			t.Fatalf("ED with %d octets of user data accepted", n)
		}
	case TypeRJ:
		if input[0] != 4 {
			t.Fatalf("RJ with LI %d accepted", input[0])
		}
		assertNoDataField(t, d.Type, input)
	case TypeDC, TypeER, TypeAK, TypeEA:
		assertNoDataField(t, d.Type, input)
	case TypeCC, TypeDR:
	}
}

// assertNoDataField checks that a decoded DC, ER, AK, EA or RJ ended with
// its header: these TPDUs have no data field (X.224 13.6.1, 13.9.1,
// 13.10.1, 13.11.1, 13.12.1).
func assertNoDataField(t *testing.T, typ TPDUType, input []byte) {
	t.Helper()
	if header := 1 + int(input[0]); len(input) != header {
		t.Fatalf("%s with %d octets after its header accepted", typ, len(input)-header)
	}
}

// describe prints every field of a decoded TPDU, for failure messages.
func describe(d Decoded) string {
	b, err := json.Marshal(d)
	if err != nil {
		return fmt.Sprintf("%+v", d)
	}
	return string(b)
}

// typedDecoders are the per-type entry points, wrapped to return a Decoded.
// A failed decode returns the zero Decoded (never a typed nil in a non-zero
// struct).
var typedDecoders = map[TPDUType]func([]byte) (Decoded, error){
	TypeCR: func(b []byte) (Decoded, error) {
		v, err := DecodeCR(b)
		if err != nil {
			return failed(v == nil, err)
		}
		return Decoded{Type: TypeCR, CR: v}, nil
	},
	TypeCC: func(b []byte) (Decoded, error) {
		v, err := DecodeCC(b)
		if err != nil {
			return failed(v == nil, err)
		}
		return Decoded{Type: TypeCC, CC: v}, nil
	},
	TypeDT: func(b []byte) (Decoded, error) {
		v, err := DecodeDT(b)
		if err != nil {
			return failed(v == nil, err)
		}
		return Decoded{Type: TypeDT, DT: v}, nil
	},
	TypeDR: func(b []byte) (Decoded, error) {
		v, err := DecodeDR(b)
		if err != nil {
			return failed(v == nil, err)
		}
		return Decoded{Type: TypeDR, DR: v}, nil
	},
	TypeDC: func(b []byte) (Decoded, error) {
		v, err := DecodeDC(b)
		if err != nil {
			return failed(v == nil, err)
		}
		return Decoded{Type: TypeDC, DC: v}, nil
	},
	TypeER: func(b []byte) (Decoded, error) {
		v, err := DecodeER(b)
		if err != nil {
			return failed(v == nil, err)
		}
		return Decoded{Type: TypeER, ER: v}, nil
	},
	TypeED: func(b []byte) (Decoded, error) {
		v, err := DecodeED(b)
		if err != nil {
			return failed(v == nil, err)
		}
		return Decoded{Type: TypeED, ED: v}, nil
	},
	TypeAK: func(b []byte) (Decoded, error) {
		v, err := DecodeAK(b)
		if err != nil {
			return failed(v == nil, err)
		}
		return Decoded{Type: TypeAK, AK: v}, nil
	},
	TypeEA: func(b []byte) (Decoded, error) {
		v, err := DecodeEA(b)
		if err != nil {
			return failed(v == nil, err)
		}
		return Decoded{Type: TypeEA, EA: v}, nil
	},
	TypeRJ: func(b []byte) (Decoded, error) {
		v, err := DecodeRJ(b)
		if err != nil {
			return failed(v == nil, err)
		}
		return Decoded{Type: TypeRJ, RJ: v}, nil
	},
}

// failed returns the zero Decoded with err, or an error that no sentinel
// matches when a failing decoder returned a value beside its error.
func failed(valueIsNil bool, err error) (Decoded, error) {
	if !valueIsNil {
		return Decoded{}, errors.New("decoder returned a value beside the error: " + err.Error())
	}
	return Decoded{}, err
}

// fuzzTyped runs one per-type decoder under assertDecodeInvariants.
func fuzzTyped(f *testing.F, typ TPDUType, seeds ...[]byte) {
	for _, s := range seeds {
		f.Add(s)
	}
	dec := typedDecoders[typ]
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := dec(data)
		assertDecodeInvariants(t, data, d, err)
	})
}

// goldenUnitFixtures loads the per-type golden TPDUs of testdata/unit.
func goldenUnitFixtures(t testing.TB) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "unit", "*.hex"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no golden fixtures in testdata/unit: %v", err)
	}
	out := make(map[string][]byte, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out[filepath.Base(p)] = b
	}
	return out
}

// richTPDUs are valid TPDUs with a variable part and, where the type has
// one, user data: the truncation table walks through every field boundary
// of them, which the minimal golden fixtures do not have.
func richTPDUs(t testing.TB) map[string][]byte {
	t.Helper()
	// Every fixed field has its own non-zero octets, so a field read from a
	// neighbouring offset changes the value.
	ref, src, nr := uint16(0x1234), uint16(0x5678), uint8(5)
	param := []Parameter{{Code: 0x85, Value: []byte{0xAA, 0xBB}}, {Code: 0x86, Value: []byte{}}, {Code: 0x87, Value: []byte{0xCC}}}
	even := []Parameter{{Code: 0x85, Value: []byte{0xAA, 0xBB}}, {Code: 0x87, Value: []byte{0xCC, 0xDD}}}
	tpdus := map[string]interface{ MarshalBinary() ([]byte, error) }{
		"CR": &CR{CDT: 3, DestinationRef: ref, SourceRef: src, ClassOption: 0x9A, CallingSelector: []byte{1, 0}, CalledSelector: []byte{1, 2},
			TPDUSize: new(uint8(0x0A)), PreferredMaxTPDUSize: new(uint32(8)), Parameters: param, UserData: []byte{0xEE, 0xEF}},
		"CC": &CC{CDT: 3, DestinationRef: ref, SourceRef: src, ClassOption: 0x9A, CallingSelector: []byte{1, 0}, CalledSelector: []byte{},
			TPDUSize: new(uint8(0x0A)), Parameters: param, UserData: []byte{0xEE}},
		"DT class 0": &DT{EOT: true, UserData: []byte{1, 2, 3}},
		"DT normal":  &DT{EOT: true, TPDUNR: &nr, DestinationRef: &ref, Parameters: even, UserData: []byte{1, 2, 3}},
		"DR":         &DR{DestinationRef: ref, SourceRef: src, Reason: 0x9A, Parameters: param, UserData: []byte{9, 8}},
		"DC":         &DC{DestinationRef: ref, SourceRef: src, Parameters: param},
		"ER":         &ER{DestinationRef: ref, RejectCause: 0x9A, Parameters: param},
		"ED":         &ED{DestinationRef: &ref, TPDUNR: &nr, EOT: true, Parameters: param, UserData: []byte{7, 8}},
		"AK":         &AK{CDT: 3, DestinationRef: ref, YRTUNR: 0x9A, Parameters: param},
		"EA":         &EA{DestinationRef: ref, YREDTUNR: 0x9A, Parameters: param},
		"RJ":         &RJ{CDT: 3, DestinationRef: ref, YRTUNR: 0x9A},
	}
	out := make(map[string][]byte, len(tpdus))
	for name, v := range tpdus {
		b, err := v.MarshalBinary()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = b
	}
	return out
}

// Every prefix of a valid TPDU either fails with ErrTooShort (the header is
// cut) or, when only user data is cut, decodes to a valid TPDU of its own;
// an ED cut down to no user data fails with ErrInvalidEDUserDataLength.
// Decode and the per-type decoder agree on every prefix.
func TestDecode_EveryPrefixOfValidTPDUs(t *testing.T) {
	inputs := goldenUnitFixtures(t)
	for name, b := range richTPDUs(t) {
		inputs[name] = b
	}
	for name, full := range inputs {
		t.Run(name, func(t *testing.T) {
			whole, err := Decode(full)
			if err != nil {
				t.Fatalf("the complete TPDU does not decode: %v", err)
			}
			assertDecodeInvariants(t, full, whole, nil)
			header := 1 + int(full[0])

			for n := range full {
				prefix := full[:n:n]
				d, err := Decode(prefix)
				assertDecodeInvariants(t, prefix, d, err)
				td, terr := typedDecoders[whole.Type](prefix)
				assertDecodeInvariants(t, prefix, td, terr)
				if (err == nil) != (terr == nil) {
					t.Fatalf("prefix of %d octets: Decode err %v, %s decoder err %v", n, err, whole.Type, terr)
				}

				switch {
				case n < header:
					if !errors.Is(err, ErrTooShort) || !errors.Is(terr, ErrTooShort) {
						t.Fatalf("prefix of %d octets (header is %d): %v / %v, want ErrTooShort", n, header, err, terr)
					}
				case whole.Type == TypeED && n == header:
					if !errors.Is(err, ErrInvalidEDUserDataLength) {
						t.Fatalf("ED cut to its header: %v, want ErrInvalidEDUserDataLength", err)
					}
				default:
					if err != nil {
						t.Fatalf("prefix of %d octets keeps the whole header (%d) and must decode: %v", n, header, err)
					}
					if d.Type != whole.Type {
						t.Fatalf("prefix of %d octets decodes as %s, the TPDU is a %s", n, d.Type, whole.Type)
					}
				}
			}
		})
	}
}

// Every prefix of a valid variable part either ends at a parameter boundary
// and parses to the parameters before it, or cuts a parameter and fails with
// ErrMalformedParameter. Both parsers are walked octet by octet.
func TestParseVariablePart_EveryPrefix(t *testing.T) {
	params := []Parameter{
		{Code: 0x85, Value: []byte{0xAA, 0xBB}},
		{Code: 0x86, Value: []byte{}},
		{Code: 0x87, Value: []byte{0xCC}},
		{Code: 0x88, Value: bytes.Repeat([]byte{0xDD}, 40)},
	}
	full, err := encodeVariablePart(params)
	if err != nil {
		t.Fatal(err)
	}
	boundaries := map[int]int{0: 0} // offset of a parameter boundary -> parameters before it
	off := 0
	for i, p := range params {
		off += 2 + len(p.Value)
		boundaries[off] = i + 1
	}

	for n := 0; n <= len(full); n++ {
		prefix := full[:n:n]
		got, err := parseVariablePart(prefix)
		crcc, crccErr := parseCRCCVariablePart(prefix)
		count, atBoundary := boundaries[n]
		if !atBoundary {
			if !errors.Is(err, ErrMalformedParameter) || got != nil {
				t.Fatalf("prefix of %d octets cuts a parameter: parseVariablePart = %v, %v; want ErrMalformedParameter", n, got, err)
			}
			if !errors.Is(crccErr, ErrMalformedParameter) || crcc != nil {
				t.Fatalf("prefix of %d octets cuts a parameter: parseCRCCVariablePart = %v, %v; want ErrMalformedParameter", n, crcc, crccErr)
			}
			continue
		}
		if err != nil || crccErr != nil {
			t.Fatalf("prefix of %d octets ends at a parameter boundary: %v / %v", n, err, crccErr)
		}
		for name, ps := range map[string][]Parameter{"parseVariablePart": got, "parseCRCCVariablePart": crcc.parameters} {
			if len(ps) != count {
				t.Fatalf("%s: prefix of %d octets gave %d parameters, want %d", name, n, len(ps), count)
			}
			for i, p := range ps {
				if p.Code != params[i].Code || !bytes.Equal(p.Value, params[i].Value) {
					t.Fatalf("%s: parameter %d = %v, want %v", name, i, p, params[i])
				}
				if !insideInput(p.Value, prefix) || cap(p.Value) != len(p.Value) {
					t.Fatalf("%s: parameter %d is not a clipped sub-slice of the input", name, i)
				}
			}
		}
	}
}

// Decoded selectors, parameter values and user data are borrowed from the
// input and clipped: appending to one of them allocates, so it changes
// neither the input buffer (inside or beyond the TPDU) nor another field.
func TestDecode_AppendToDecodedSliceLeavesInputAlone(t *testing.T) {
	inputs := goldenUnitFixtures(t)
	for name, b := range richTPDUs(t) {
		inputs[name] = b
	}
	for name, tpdu := range inputs {
		t.Run(name, func(t *testing.T) {
			// The TPDU sits inside a larger receive buffer: octets follow it.
			const guard = 0x77
			buffer := append(bytes.Clone(tpdu), bytes.Repeat([]byte{guard}, 16)...)
			pristine := bytes.Clone(buffer)
			input := buffer[:len(tpdu)]

			d, err := Decode(input)
			if err != nil {
				t.Fatal(err)
			}
			// The same TPDU decoded from a buffer nobody appends to.
			reference, err := Decode(bytes.Clone(tpdu))
			if err != nil {
				t.Fatal(err)
			}

			for field, s := range decodedSlices(d) {
				grown := append(s, 0xFF, 0xFF, 0xFF, 0xFF)
				if len(grown) != len(s)+4 {
					t.Fatalf("%s: append returned %d octets", field, len(grown))
				}
				if !bytes.Equal(buffer, pristine) {
					t.Fatalf("append to %s wrote into the input buffer:\n was % x\n now % x", field, pristine, buffer)
				}
				if !reflect.DeepEqual(d, reference) {
					t.Fatalf("append to %s changed another decoded field:\n was %s\n now %s", field, describe(reference), describe(d))
				}
			}

			// The aliasing itself is the contract and stays: a decoded field
			// reads the input buffer, clipped to its own octets.
			assertBorrowed(t, d, input)
		})
	}
}

// A DT in the extended class 2 to 4 format has a 7-octet fixed part (X.224
// §13.7.1 c), so its LI is odd; §13.7.4 NOTE gives the rule that an even LI
// is the normal format and an odd LI the extended one. DecodeDT rejects
// every odd LI with ErrUnsupportedDTVariant, as the documents say.
func TestDecodeDT_OddLIIsTheExtendedFormat(t *testing.T) {
	// extended builds a DT in the extended format: LI, DT code, DST-REF,
	// four octets of EOT and TPDU-NR, an optional variable part, user data.
	extended := func(seq [4]byte, variable, user []byte) []byte {
		b := []byte{byte(7 + len(variable)), 0xF0, 0x12, 0x34, seq[0], seq[1], seq[2], seq[3]}
		b = append(b, variable...)
		return append(b, user...)
	}
	checksum := []byte{0xC3, 0x02, 0xAB, 0xCD} // X.224 §13.2.3.1

	cases := []struct {
		name string
		b    []byte
	}{
		{"sequence number zero", extended([4]byte{0x00, 0x00, 0x00, 0x00}, nil, []byte{0xDE, 0xAD})},
		{"sequence number in octet 5", extended([4]byte{0x7F, 0x00, 0x00, 0x00}, nil, []byte{0xDE})},
		{"sequence number in octet 6", extended([4]byte{0x00, 0x01, 0x00, 0x00}, nil, []byte{0xDE})},
		{"sequence number in octet 7", extended([4]byte{0x00, 0x00, 0x01, 0x00}, nil, []byte{0xDE})},
		{"sequence number in octet 8", extended([4]byte{0x00, 0x00, 0x00, 0x01}, nil, []byte{0xDE})},
		{"sequence number in every octet", extended([4]byte{0x12, 0x34, 0x56, 0x78}, nil, []byte{0xDE})},
		{"EOT set", extended([4]byte{0x80, 0x00, 0x00, 0x02}, nil, []byte{0xDE})},
		{"sequence number 0x00850109", extended([4]byte{0x00, 0x85, 0x01, 0x09}, nil, nil)},
		{"sequence number 0x01850085 and a two-octet variable part", extended([4]byte{0x01, 0x85, 0x00, 0x85}, []byte{0x00, 0x00}, nil)},
		{"with a checksum parameter (LI 11)", extended([4]byte{0x00, 0x00, 0x00, 0x05}, checksum, []byte{0xDE})},
		{"no user data", extended([4]byte{0x00, 0x00, 0x00, 0x05}, nil, nil)},
		{"ROA bit set", append([]byte{0x07, 0xF1}, extended([4]byte{0, 0, 0, 5}, nil, nil)[2:]...)},
		{"LI 5", []byte{0x05, 0xF0, 0x12, 0x34, 0x01, 0x00, 0xDE}},
		{"largest odd LI", append([]byte{253, 0xF0}, make([]byte, 252)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.b[0]%2 == 0 {
				t.Fatalf("test input has an even LI %d", tc.b[0])
			}
			for entry, decode := range map[string]func([]byte) error{
				"DecodeDT":        func(b []byte) error { _, err := DecodeDT(b); return err },
				"Decode":          func(b []byte) error { _, err := Decode(b); return err },
				"DecodeWithRaw":   func(b []byte) error { _, err := DecodeWithRaw(b); return err },
				"ExtractUserData": func(b []byte) error { _, err := ExtractUserData(b); return err },
			} {
				if err := decode(tc.b); !errors.Is(err, ErrUnsupportedDTVariant) {
					t.Errorf("%s(% x) = %v, want ErrUnsupportedDTVariant", entry, tc.b, err)
				}
			}
		})
	}
}

// DC, ER, AK, EA and RJ have no data field: their structures end with the
// header (X.224 13.6.1, 13.9.1, 13.10.1, 13.11.1, 13.12.1), and a TPDU that
// does not comply with its structure is invalid (3.2.16). Every decoder
// entry point refuses octets after their header with ErrLengthMismatch, and
// decodes the same TPDU without them.
func TestDecode_NoOctetsAfterTheHeaderOfTPDUsWithoutDataField(t *testing.T) {
	ref, src := uint16(0x1234), uint16(0x5678)
	param := []Parameter{{Code: 0x85, Value: []byte{0xAA, 0xBB}}}
	tpdus := map[string]interface{ MarshalBinary() ([]byte, error) }{
		"DC":                    &DC{DestinationRef: ref, SourceRef: src},
		"DC with a parameter":   &DC{DestinationRef: ref, SourceRef: src, Parameters: param},
		"ER":                    &ER{DestinationRef: ref, RejectCause: 2},
		"ER with a parameter":   &ER{DestinationRef: ref, RejectCause: 2, Parameters: param},
		"AK":                    &AK{CDT: 3, DestinationRef: ref, YRTUNR: 4},
		"AK with a parameter":   &AK{CDT: 3, DestinationRef: ref, YRTUNR: 4, Parameters: param},
		"EA":                    &EA{DestinationRef: ref, YREDTUNR: 4},
		"EA with a parameter":   &EA{DestinationRef: ref, YREDTUNR: 4, Parameters: param},
		"RJ (no variable part)": &RJ{CDT: 3, DestinationRef: ref, YRTUNR: 4},
	}
	entries := map[string]func([]byte) error{
		"Decode":        func(b []byte) error { _, err := Decode(b); return err },
		"DecodeWithRaw": func(b []byte) error { _, err := DecodeWithRaw(b); return err },
	}
	for name, v := range tpdus {
		t.Run(name, func(t *testing.T) {
			header, err := v.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			whole, err := Decode(header)
			if err != nil {
				t.Fatalf("% x without octets after the header: %v", header, err)
			}
			typed := typedDecoders[whole.Type]
			if d, err := typed(header); err != nil || !reflect.DeepEqual(d, whole) {
				t.Fatalf("%s decoder on % x: %v, %v", whole.Type, header, describe(d), err)
			}
			for _, extra := range [][]byte{{0x00}, {0xDE, 0xAD}, bytes.Repeat([]byte{0x01}, 64)} {
				b := append(bytes.Clone(header), extra...)
				if _, err := typed(b); !errors.Is(err, ErrLengthMismatch) {
					t.Errorf("%s decoder with %d octets after the header: %v, want ErrLengthMismatch", whole.Type, len(extra), err)
				}
				for entry, decode := range entries {
					if err := decode(b); !errors.Is(err, ErrLengthMismatch) {
						t.Errorf("%s with %d octets after the header: %v, want ErrLengthMismatch", entry, len(extra), err)
					}
				}
			}
		})
	}
}

// The LI of a DT selects its format. Every value is either the class 0 and 1
// format (2), the normal class 2 to 4 format (even, 4 or more) or refused.
func TestDecodeDT_EveryLI(t *testing.T) {
	for li := 0; li <= 255; li++ {
		b := make([]byte, 1+li+2) // the header LI announces, and two octets of user data
		b[0], b[1] = byte(li), 0xF0
		dt, err := DecodeDT(b)
		switch {
		case li == 255:
			if !errors.Is(err, ErrInvalidLI) {
				t.Errorf("LI 255: %v, want ErrInvalidLI", err)
			}
		case li == 2:
			if err != nil || dt.DestinationRef != nil || len(dt.UserData) != 2 {
				t.Errorf("LI 2: %v, %v; want the class 0 and 1 format", dt, err)
			}
		case li >= 4 && li%2 == 0:
			// The variable part is zero octets here: parameters 0x00 of
			// length 0, which the generic parser accepts.
			if err != nil || dt.DestinationRef == nil || len(dt.UserData) != 2 {
				t.Errorf("LI %d: %v, %v; want the normal class 2 to 4 format", li, dt, err)
			}
		default:
			if !errors.Is(err, ErrUnsupportedDTVariant) {
				t.Errorf("LI %d: %v, want ErrUnsupportedDTVariant", li, err)
			}
		}
	}
}
