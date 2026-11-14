// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// assertDecodedInvariant checks that d has exactly one non-nil TPDU pointer and Type matches it.
// Call for every successful Decode result so the invariant is mechanically enforced.
func assertDecodedInvariant(t *testing.T, d Decoded) {
	t.Helper()
	var count int
	if d.CR != nil {
		count++
		if d.Type != TypeCR {
			t.Errorf("invariant: CR non-nil but Type=%s", d.Type)
		}
	}
	if d.CC != nil {
		count++
		if d.Type != TypeCC {
			t.Errorf("invariant: CC non-nil but Type=%s", d.Type)
		}
	}
	if d.DT != nil {
		count++
		if d.Type != TypeDT {
			t.Errorf("invariant: DT non-nil but Type=%s", d.Type)
		}
	}
	if d.DR != nil {
		count++
		if d.Type != TypeDR {
			t.Errorf("invariant: DR non-nil but Type=%s", d.Type)
		}
	}
	if d.DC != nil {
		count++
		if d.Type != TypeDC {
			t.Errorf("invariant: DC non-nil but Type=%s", d.Type)
		}
	}
	if d.ER != nil {
		count++
		if d.Type != TypeER {
			t.Errorf("invariant: ER non-nil but Type=%s", d.Type)
		}
	}
	if d.ED != nil {
		count++
		if d.Type != TypeED {
			t.Errorf("invariant: ED non-nil but Type=%s", d.Type)
		}
	}
	if d.AK != nil {
		count++
		if d.Type != TypeAK {
			t.Errorf("invariant: AK non-nil but Type=%s", d.Type)
		}
	}
	if d.EA != nil {
		count++
		if d.Type != TypeEA {
			t.Errorf("invariant: EA non-nil but Type=%s", d.Type)
		}
	}
	if d.RJ != nil {
		count++
		if d.Type != TypeRJ {
			t.Errorf("invariant: RJ non-nil but Type=%s", d.Type)
		}
	}
	if count != 1 {
		t.Errorf("invariant: exactly one TPDU must be non-nil, got %d (CR=%v CC=%v DT=%v DR=%v DC=%v ER=%v ED=%v AK=%v EA=%v RJ=%v)",
			count, d.CR != nil, d.CC != nil, d.DT != nil, d.DR != nil, d.DC != nil, d.ER != nil, d.ED != nil, d.AK != nil, d.EA != nil, d.RJ != nil)
	}
}

func TestDecode_CR(t *testing.T) {
	d, err := Decode(minimalCR)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertDecodedInvariant(t, d)
	if d.Type != TypeCR || d.CR == nil {
		t.Fatalf("Type=%s CR=%v", d.Type, d.CR != nil)
	}
	if d.CR.DestinationRef != 0 || d.CR.SourceRef != 0 {
		t.Errorf("CR refs: %d %d", d.CR.DestinationRef, d.CR.SourceRef)
	}
}

func TestDecode_CC(t *testing.T) {
	d, err := Decode(minimalCC)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertDecodedInvariant(t, d)
	if d.Type != TypeCC || d.CC == nil {
		t.Fatalf("Type=%s CC=%v", d.Type, d.CC != nil)
	}
}

func TestDecode_DT(t *testing.T) {
	d, err := Decode(minimalDT)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertDecodedInvariant(t, d)
	if d.Type != TypeDT || d.DT == nil {
		t.Fatalf("Type=%s DT=%v", d.Type, d.DT != nil)
	}
	if len(d.DT.UserData) != 0 {
		t.Errorf("UserData = %v", d.DT.UserData)
	}
}

func TestDecode_Errors(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
	}{
		{"too short", []byte{0x01}, ErrTooShort},
		{"bad LI", []byte{0xFF, 0xE0}, ErrInvalidLI},
		{"malformed ED (too short)", []byte{0x02, 0x10, 0x00}, ErrTooShort},
		{"reserved code", []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ErrReservedTPDU},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := Decode(tt.b)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("err = %v, want Is(%v)", err, tt.wantErr)
				}
				if d.CR != nil || d.CC != nil || d.DT != nil {
					t.Error("Decoded must be zero value on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertDecodedInvariant(t, d)
		})
	}
}

func TestDecode_RoundTrip_CR(t *testing.T) {
	d, err := Decode(minimalCR)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertDecodedInvariant(t, d)
	out, err := d.CR.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	d2, err := Decode(out)
	if err != nil {
		t.Fatalf("Decode round-trip: %v", err)
	}
	assertDecodedInvariant(t, d2)
	if d2.CR == nil || d.CR.DestinationRef != d2.CR.DestinationRef || d.CR.SourceRef != d2.CR.SourceRef {
		t.Errorf("canonical equivalence: %+v vs %+v", d.CR, d2.CR)
	}
}

func TestDecode_RoundTrip_CC(t *testing.T) {
	d, err := Decode(minimalCC)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertDecodedInvariant(t, d)
	out, err := d.CC.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	d2, err := Decode(out)
	if err != nil {
		t.Fatalf("Decode round-trip: %v", err)
	}
	assertDecodedInvariant(t, d2)
	if d2.CC == nil || d.CC.DestinationRef != d2.CC.DestinationRef || d.CC.SourceRef != d2.CC.SourceRef {
		t.Errorf("canonical equivalence: %+v vs %+v", d.CC, d2.CC)
	}
}

func TestDecode_RoundTrip_DT(t *testing.T) {
	d, err := Decode(minimalDT)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertDecodedInvariant(t, d)
	out, err := d.DT.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	d2, err := Decode(out)
	if err != nil {
		t.Fatalf("Decode round-trip: %v", err)
	}
	assertDecodedInvariant(t, d2)
	if !bytes.Equal(d2.DT.UserData, d.DT.UserData) {
		t.Errorf("UserData: got %x want %x", d2.DT.UserData, d.DT.UserData)
	}
}

func TestDecodeWithRaw(t *testing.T) {
	b := minimalCR
	d, err := DecodeWithRaw(b)
	if err != nil {
		t.Fatalf("DecodeWithRaw: %v", err)
	}
	assertDecodedInvariant(t, d)
	if d.Raw == nil {
		t.Fatal("Raw should be set")
	}
	if len(d.Raw) != len(b) {
		t.Errorf("len(Raw) = %d, want %d", len(d.Raw), len(b))
	}
	if !bytes.Equal(d.Raw, b) {
		t.Errorf("Raw = %x, want %x", d.Raw, b)
	}
	// Raw must be the same slice (alias)
	if len(b) > 0 && (len(d.Raw) == 0 || &d.Raw[0] != &b[0]) {
		t.Error("Raw should alias input b")
	}
}

func TestDecodeWithRaw_Replay(t *testing.T) {
	for _, b := range [][]byte{minimalCR, minimalCC, minimalDT, minimalDR, minimalED, minimalAK, minimalEA, minimalRJ} {
		d, err := DecodeWithRaw(b)
		if err != nil {
			t.Errorf("DecodeWithRaw(%x): %v", b, err)
			continue
		}
		// Re-decode Raw and compare Type and that we get the same variant
		d2, err := Decode(d.Raw)
		if err != nil {
			t.Errorf("Decode(Raw) for %s: %v", d.Type, err)
			continue
		}
		if d2.Type != d.Type {
			t.Errorf("replay Type = %s, want %s", d2.Type, d.Type)
		}
		assertDecodedInvariant(t, d2)
	}
}

func TestDecodeWithRaw_OnError(t *testing.T) {
	bad := []byte{0x01} // too short
	d, err := DecodeWithRaw(bad)
	if err == nil {
		t.Fatal("expected error")
	}
	if d.Raw != nil {
		t.Error("Raw must be nil on error")
	}
	if d.Type != 0 || d.CR != nil {
		t.Error("Decoded must be zero value on error")
	}
}

func TestDecode_DoesNotSetRaw(t *testing.T) {
	d, err := Decode(minimalCR)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.Raw != nil {
		t.Error("Decode must not set Raw")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(minimalCR)
	f.Add(minimalCC)
	f.Add(minimalDT)
	f.Add([]byte{0x07, 0x80, 0x00, 0x01, 0x00, 0x02, 0x01}) // minimal DR
	f.Add([]byte{0x05, 0xC0, 0x00, 0x01, 0x00, 0x02})       // minimal DC
	f.Add([]byte{0x04, 0x70, 0x00, 0x01, 0x02})             // minimal ER
	f.Add([]byte{0x04, 0x10, 0x00, 0x00, 0x00, 0x01})       // minimal ED
	f.Add([]byte{0x04, 0x60, 0x00, 0x00, 0x00})             // minimal AK
	f.Add([]byte{0x04, 0x20, 0x00, 0x00, 0x00})             // minimal EA
	f.Add([]byte{0x04, 0x50, 0x00, 0x00, 0x00})             // minimal RJ
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Decode(data)
		if err != nil {
			if d.Type != 0 || d.CR != nil || d.CC != nil || d.DT != nil || d.DR != nil ||
				d.DC != nil || d.ER != nil || d.ED != nil || d.AK != nil || d.EA != nil || d.RJ != nil || d.Raw != nil {
				t.Fatalf("Decode error must return zero Decoded, got Type=%v", d.Type)
			}
		}
		assertDecodeInvariants(t, data, d, err)

		// DecodeWithRaw is Decode plus the input itself as Raw.
		withRaw, rawErr := DecodeWithRaw(data)
		if (rawErr == nil) != (err == nil) {
			t.Fatalf("DecodeWithRaw err %v, Decode err %v", rawErr, err)
		}
		if err == nil {
			if len(withRaw.Raw) != len(data) || (len(data) > 0 && &withRaw.Raw[0] != &data[0]) {
				t.Fatal("DecodeWithRaw: Raw is not the input slice")
			}
			withRaw.Raw = nil
			if !reflect.DeepEqual(withRaw, d) {
				t.Fatal("DecodeWithRaw and Decode return different values")
			}
		} else if !reflect.DeepEqual(withRaw, Decoded{}) {
			t.Fatal("DecodeWithRaw failed and returned a value")
		}
	})
}

// The per-type decoder targets assert the invariants of
// assertDecodeInvariants (codec_invariants_test.go) on every input: a
// documented sentinel on failure; on success borrowed and clipped slices, a
// round trip through the encoder that is deeply equal, the exact octets back
// for the types with one encoding, and agreement with Decode.

func FuzzDecodeCR(f *testing.F) {
	fuzzTyped(f, TypeCR, minimalCR, richTPDUs(f)["CR"])
}

func FuzzDecodeCC(f *testing.F) {
	fuzzTyped(f, TypeCC, minimalCC, richTPDUs(f)["CC"])
}

func FuzzDecodeDT(f *testing.F) {
	fuzzTyped(f, TypeDT, minimalDT, richTPDUs(f)["DT class 0"], richTPDUs(f)["DT normal"],
		// Extended format (odd LI): refused, X.224 §13.7.4 NOTE.
		[]byte{0x07, 0xF0, 0x12, 0x34, 0x00, 0x85, 0x01, 0x09})
}

func FuzzDecodeDR(f *testing.F) {
	fuzzTyped(f, TypeDR, minimalDR, richTPDUs(f)["DR"])
}

func FuzzDecodeDC(f *testing.F) {
	fuzzTyped(f, TypeDC, minimalDC, richTPDUs(f)["DC"])
}

func FuzzDecodeER(f *testing.F) {
	fuzzTyped(f, TypeER, minimalER, richTPDUs(f)["ER"])
}

func FuzzDecodeED(f *testing.F) {
	fuzzTyped(f, TypeED, minimalED, richTPDUs(f)["ED"])
}

func FuzzDecodeAK(f *testing.F) {
	fuzzTyped(f, TypeAK, minimalAK, richTPDUs(f)["AK"])
}

func FuzzDecodeEA(f *testing.F) {
	fuzzTyped(f, TypeEA, minimalEA, richTPDUs(f)["EA"])
}

func FuzzDecodeRJ(f *testing.F) {
	fuzzTyped(f, TypeRJ, minimalRJ, richTPDUs(f)["RJ"])
}

// FuzzLooksLikeDoesNotPanic keeps its name for the corpus. The LooksLike
// helpers classify by the same header checks and type masks as PeekType: at
// most one of them answers true, the one that does names the type PeekType
// returns, and a TPDU that Decode accepts is recognised by the helper of its
// type.
func FuzzLooksLikeDoesNotPanic(f *testing.F) {
	f.Add(minimalCR)
	f.Add(minimalDT)
	f.Add([]byte{0xFF})
	f.Add([]byte{})
	for _, b := range richTPDUs(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		looks := map[TPDUType]bool{
			TypeCR: LooksLikeCR(data),
			TypeCC: LooksLikeCC(data),
			TypeDR: LooksLikeDR(data),
			TypeDC: LooksLikeDC(data),
			TypeDT: LooksLikeDT(data),
			TypeER: LooksLikeER(data),
			TypeED: LooksLikeED(data),
			TypeAK: LooksLikeAK(data),
			TypeEA: LooksLikeEA(data),
			TypeRJ: LooksLikeRJ(data),
		}
		peeked, peekErr := PeekType(data)
		// The helpers also require the header LI announces to be present.
		headerPresent := peekErr == nil && len(data) >= 1+int(data[0])
		for typ, yes := range looks {
			if want := headerPresent && typ == peeked; yes != want {
				t.Fatalf("LooksLike%s(% x) = %v; PeekType = %s, %v; header present = %v", typ, data, yes, peeked, peekErr, headerPresent)
			}
		}
		connection := peekErr == nil && (peeked == TypeCR || peeked == TypeCC || peeked == TypeDR || peeked == TypeDC)
		if got := IsConnectionOriented(data); got != connection {
			t.Fatalf("IsConnectionOriented(% x) = %v; PeekType = %s, %v", data, got, peeked, peekErr)
		}
		if d, err := Decode(data); err == nil && !looks[d.Type] {
			t.Fatalf("Decode accepts % x as %s, LooksLike%s does not", data, d.Type, d.Type)
		}
	})
}

// FuzzMarshalDecodeRoundTrip: whatever Decode accepts encodes again, and the
// encoding decodes to a deeply equal value (assertDecodeInvariants).
func FuzzMarshalDecodeRoundTrip(f *testing.F) {
	f.Add(minimalCR)
	f.Add(minimalCC)
	f.Add(minimalDT)
	f.Add(minimalDR)
	f.Add(minimalED)
	for _, b := range richTPDUs(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Decode(data)
		assertDecodeInvariants(t, data, d, err)
	})
}
