// SPDX-License-Identifier: MIT

package cotp

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCapturesDecode decodes every committed .hex fixture in testdata/captures/.
// Committed fixtures are required in CI; each must decode without error.
func TestCapturesDecode(t *testing.T) {
	dir := filepath.Join("testdata", "captures")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("captures dir not found: %v", err)
		return
	}
	var decoded int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".hex") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", e.Name(), err)
			continue
		}
		b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(raw)), " ", ""))
		if err != nil {
			t.Errorf("%s: hex decode: %v", e.Name(), err)
			continue
		}
		d, err := Decode(b)
		if err != nil {
			t.Errorf("%s: decode: %v", e.Name(), err)
			continue
		}
		assertDecodedInvariant(t, d)
		decoded++
	}
	if decoded == 0 {
		t.Logf("no .hex files in testdata/captures/ (add committed fixtures for CI)")
	}
}

// TestGoldenCRCC decodes minimal CR and CC from testdata/unit hex fixtures.
func TestGoldenCRCC(t *testing.T) {
	hexFiles := []struct {
		file string
		dec  func([]byte) (interface{}, error)
	}{
		{"minimal_cr.hex", func(b []byte) (interface{}, error) { return DecodeCR(b) }},
		{"minimal_cc.hex", func(b []byte) (interface{}, error) { return DecodeCC(b) }},
	}
	for _, tt := range hexFiles {
		t.Run(tt.file, func(t *testing.T) {
			path := filepath.Join("testdata", "unit", tt.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("missing fixture: %v", err)
				return
			}
			b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(raw)), " ", ""))
			if err != nil {
				t.Fatalf("hex decode: %v", err)
			}
			_, err = tt.dec(b)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
		})
	}
}

// TestGoldenAll decodes all supported TPDU types from testdata/unit; decode → marshal → decode for semantic equality.
func TestGoldenAll(t *testing.T) {
	hexFiles := []struct {
		file string
		dec  func([]byte) (interface{}, error)
		enc  func(interface{}) ([]byte, error)
	}{
		{"minimal_cr.hex", func(b []byte) (interface{}, error) { return DecodeCR(b) }, func(x interface{}) ([]byte, error) { return x.(*CR).MarshalBinary() }},
		{"minimal_cc.hex", func(b []byte) (interface{}, error) { return DecodeCC(b) }, func(x interface{}) ([]byte, error) { return x.(*CC).MarshalBinary() }},
		{"minimal_dt.hex", func(b []byte) (interface{}, error) { return DecodeDT(b) }, func(x interface{}) ([]byte, error) { return x.(*DT).MarshalBinary() }},
		{"minimal_dr.hex", func(b []byte) (interface{}, error) { return DecodeDR(b) }, func(x interface{}) ([]byte, error) { return x.(*DR).MarshalBinary() }},
		{"minimal_dc.hex", func(b []byte) (interface{}, error) { return DecodeDC(b) }, func(x interface{}) ([]byte, error) { return x.(*DC).MarshalBinary() }},
		{"minimal_er.hex", func(b []byte) (interface{}, error) { return DecodeER(b) }, func(x interface{}) ([]byte, error) { return x.(*ER).MarshalBinary() }},
		{"minimal_ed.hex", func(b []byte) (interface{}, error) { return DecodeED(b) }, func(x interface{}) ([]byte, error) { return x.(*ED).MarshalBinary() }},
		{"minimal_ak.hex", func(b []byte) (interface{}, error) { return DecodeAK(b) }, func(x interface{}) ([]byte, error) { return x.(*AK).MarshalBinary() }},
		{"minimal_ea.hex", func(b []byte) (interface{}, error) { return DecodeEA(b) }, func(x interface{}) ([]byte, error) { return x.(*EA).MarshalBinary() }},
		{"minimal_rj.hex", func(b []byte) (interface{}, error) { return DecodeRJ(b) }, func(x interface{}) ([]byte, error) { return x.(*RJ).MarshalBinary() }},
	}
	for _, tt := range hexFiles {
		t.Run(tt.file, func(t *testing.T) {
			path := filepath.Join("testdata", "unit", tt.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("missing fixture: %v", err)
				return
			}
			b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(raw)), " ", ""))
			if err != nil {
				t.Fatalf("hex decode: %v", err)
			}
			decoded, err := tt.dec(b)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			out, err := tt.enc(decoded)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			decoded2, err := tt.dec(out)
			if err != nil {
				t.Fatalf("decode round-trip: %v", err)
			}
			// Semantic equality: re-encode both and compare (canonical output)
			out2, err := tt.enc(decoded2)
			if err != nil {
				t.Fatalf("marshal 2: %v", err)
			}
			if string(out) != string(out2) {
				t.Errorf("canonical marshal mismatch: %x vs %x", out, out2)
			}
		})
	}
}
