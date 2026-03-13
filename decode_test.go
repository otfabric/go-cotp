package cotp

import (
	"bytes"
	"errors"
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
		_, _ = Decode(data)
		// No panic; errors are acceptable. Invariant: Decode never partially fills on error.
	})
}

func FuzzDecodeCR(f *testing.F) {
	f.Add(minimalCR)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeCR(data)
	})
}

func FuzzDecodeCC(f *testing.F) {
	f.Add(minimalCC)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeCC(data)
	})
}

func FuzzDecodeDT(f *testing.F) {
	f.Add(minimalDT)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeDT(data)
	})
}

func FuzzDecodeDR(f *testing.F) {
	f.Add(minimalDR)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeDR(data)
	})
}

func FuzzDecodeDC(f *testing.F) {
	f.Add(minimalDC)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeDC(data)
	})
}

func FuzzDecodeER(f *testing.F) {
	f.Add(minimalER)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeER(data)
	})
}

func FuzzDecodeED(f *testing.F) {
	f.Add(minimalED)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeED(data)
	})
}

func FuzzDecodeAK(f *testing.F) {
	f.Add(minimalAK)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeAK(data)
	})
}

func FuzzDecodeEA(f *testing.F) {
	f.Add(minimalEA)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeEA(data)
	})
}

func FuzzDecodeRJ(f *testing.F) {
	f.Add(minimalRJ)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeRJ(data)
	})
}
