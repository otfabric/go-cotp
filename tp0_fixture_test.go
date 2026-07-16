// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readTP0Hex(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "tp0", rel))
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(raw)), " ", ""))
	if err != nil {
		t.Fatalf("%s: hex: %v", rel, err)
	}
	return b
}

func assertRoundTrip(t *testing.T, want []byte, v interface{ MarshalBinary() ([]byte, error) }) {
	t.Helper()
	got, err := v.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encode mismatch\n got %x\nwant %x", got, want)
	}
}

func TestTP0Fixture_S7Connect(t *testing.T) {
	b := readTP0Hex(t, "connect/s7_cr_tsap1024.hex")
	cr, err := DecodeCR(b)
	if err != nil {
		t.Fatal(err)
	}
	if cr.SourceRef != 0x0001 || cr.DestinationRef != 0 {
		t.Fatalf("refs DST=%d SRC=%d", cr.DestinationRef, cr.SourceRef)
	}
	if !bytes.Equal(cr.CallingSelector, []byte{0x01, 0x00}) || !bytes.Equal(cr.CalledSelector, []byte{0x01, 0x01}) {
		t.Fatalf("selectors calling=%x called=%x", cr.CallingSelector, cr.CalledSelector)
	}
	if cr.TPDUSize == nil || *cr.TPDUSize != 0x0A {
		t.Fatalf("TPDUSize = %v, want 0x0A (1024)", cr.TPDUSize)
	}
	assertRoundTrip(t, b, cr)

	ccb := readTP0Hex(t, "accept/s7_cc_tsap1024.hex")
	cc, err := DecodeCC(ccb)
	if err != nil {
		t.Fatal(err)
	}
	if cc.DestinationRef != 0x0001 || cc.SourceRef != 0x0002 {
		t.Fatalf("CC refs DST=%d SRC=%d", cc.DestinationRef, cc.SourceRef)
	}
	if cc.TPDUSize == nil || *cc.TPDUSize != 0x0A {
		t.Fatalf("CC TPDUSize = %v", cc.TPDUSize)
	}
	assertRoundTrip(t, ccb, cc)
}

func TestTP0Fixture_MMSConnectOmittedSize(t *testing.T) {
	b := readTP0Hex(t, "connect/mms_cr_selectors.hex")
	cr, err := DecodeCR(b)
	if err != nil {
		t.Fatal(err)
	}
	if cr.SourceRef != 0x1234 || cr.TPDUSize != nil || cr.PreferredMaxTPDUSize != nil {
		t.Fatalf("want omitted size; got size=%v pref=%v src=%d", cr.TPDUSize, cr.PreferredMaxTPDUSize, cr.SourceRef)
	}
	if !bytes.Equal(cr.CallingSelector, []byte{0x00, 0x01}) || !bytes.Equal(cr.CalledSelector, []byte{0x00, 0x01}) {
		t.Fatalf("selectors %x / %x", cr.CallingSelector, cr.CalledSelector)
	}
	assertRoundTrip(t, b, cr)
}

func TestTP0Fixture_PreferredMax(t *testing.T) {
	b := readTP0Hex(t, "connect/preferred_max_cr.hex")
	cr, err := DecodeCR(b)
	if err != nil {
		t.Fatal(err)
	}
	if cr.TPDUSize == nil || *cr.TPDUSize != 0x0A {
		t.Fatalf("standard size = %v", cr.TPDUSize)
	}
	if cr.PreferredMaxTPDUSize == nil || *cr.PreferredMaxTPDUSize != 8 {
		t.Fatalf("preferred units = %v, want 8", cr.PreferredMaxTPDUSize)
	}
	assertRoundTrip(t, b, cr)

	ccb := readTP0Hex(t, "accept/preferred_max_cc.hex")
	cc, err := DecodeCC(ccb)
	if err != nil {
		t.Fatal(err)
	}
	if cc.TPDUSize != nil {
		t.Fatalf("CC must confirm via 0xF0 only, got 0xC0=%v", cc.TPDUSize)
	}
	if cc.PreferredMaxTPDUSize == nil || *cc.PreferredMaxTPDUSize != 7 {
		t.Fatalf("CC preferred units = %v, want 7 (896)", cc.PreferredMaxTPDUSize)
	}
	assertRoundTrip(t, ccb, cc)
}

func TestTP0Fixture_SegmentedDT(t *testing.T) {
	non := readTP0Hex(t, "data/dt_seg_non_eot.hex")
	eot := readTP0Hex(t, "data/dt_seg_eot.hex")
	d1, err := DecodeDT(non)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := DecodeDT(eot)
	if err != nil {
		t.Fatal(err)
	}
	if d1.EOT || !bytes.Equal(d1.UserData, []byte{0xAA, 0xBB}) {
		t.Fatalf("non-EOT = %+v", d1)
	}
	if !d2.EOT || !bytes.Equal(d2.UserData, []byte{0xCC}) {
		t.Fatalf("EOT = %+v", d2)
	}
	assertRoundTrip(t, non, d1)
	assertRoundTrip(t, eot, d2)
}

func TestTP0Fixture_RejectDRAndER(t *testing.T) {
	drb := readTP0Hex(t, "reject/dr_refuse_congestion.hex")
	dr, err := DecodeDR(drb)
	if err != nil {
		t.Fatal(err)
	}
	if DisconnectReason(dr.Reason) != ReasonCongestionAtTSAP {
		t.Fatalf("reason = %d", dr.Reason)
	}
	assertRoundTrip(t, drb, dr)

	erb := readTP0Hex(t, "reject/er_invalid_parameter_value.hex")
	er, err := DecodeER(erb)
	if err != nil {
		t.Fatal(err)
	}
	if er.RejectCause != erCauseInvalidParameterValue {
		t.Fatalf("cause = %d", er.RejectCause)
	}
	assertRoundTrip(t, erb, er)
}

func TestTP0Fixture_AllDecode(t *testing.T) {
	root := filepath.Join("testdata", "tp0")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".hex") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(raw)), " ", ""))
		if err != nil {
			t.Errorf("%s: hex: %v", path, err)
			return nil
		}
		msg, err := Decode(b)
		if err != nil {
			t.Errorf("%s: decode: %v", path, err)
			return nil
		}
		assertDecodedInvariant(t, msg)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
