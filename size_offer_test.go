// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"testing"
)

func TestBuildSizeOffer_Cases(t *testing.T) {
	t.Run("case_1_configured_0_compat_omits", func(t *testing.T) {
		b, err := buildSizeOffer(0, SizeProfileRFC1006Compat)
		if err != nil {
			t.Fatal(err)
		}
		if !b.Offer.Omitted || b.StandardCode != nil || b.PreferredUnits != nil {
			t.Fatalf("%+v", b)
		}
	})
	t.Run("case_1_configured_0_preferred_maximum", func(t *testing.T) {
		b, err := buildSizeOffer(0, SizeProfilePreferredMaximum)
		if err != nil {
			t.Fatal(err)
		}
		// fallbackStandard(65408) returns 0x0F (32768) since the table was
		// extended to include 0x0F–0x10 for iec61850bean interoperability.
		if b.StandardCode == nil || *b.StandardCode != 0x0F {
			t.Fatalf("std=%v", b.StandardCode)
		}
		if b.PreferredUnits == nil || *b.PreferredUnits != 511 {
			t.Fatalf("pref=%v", b.PreferredUnits)
		}
		if b.Offer.Preferred == nil || *b.Offer.Preferred != 65408 {
			t.Fatalf("offer pref=%v", b.Offer.Preferred)
		}
	})
	t.Run("case_2_configured_below_128", func(t *testing.T) {
		_, err := buildSizeOffer(127, SizeProfileRFC1006Compat)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_3_exact_128_compat", func(t *testing.T) {
		b, err := buildSizeOffer(128, SizeProfileRFC1006Compat)
		if err != nil {
			t.Fatal(err)
		}
		if b.StandardCode == nil || *b.StandardCode != 0x07 || b.PreferredUnits != nil {
			t.Fatalf("%+v", b)
		}
	})
	t.Run("case_3_exact_128_preferred_maximum", func(t *testing.T) {
		b, err := buildSizeOffer(128, SizeProfilePreferredMaximum)
		if err != nil {
			t.Fatal(err)
		}
		if b.StandardCode == nil || *b.StandardCode != 0x07 {
			t.Fatalf("std=%v", b.StandardCode)
		}
		if b.PreferredUnits == nil || *b.PreferredUnits != 1 {
			t.Fatalf("pref=%v", b.PreferredUnits)
		}
	})
	t.Run("case_4_exact_1024_compat", func(t *testing.T) {
		b, err := buildSizeOffer(1024, SizeProfileRFC1006Compat)
		if err != nil {
			t.Fatal(err)
		}
		if b.StandardCode == nil || *b.StandardCode != 0x0A || b.PreferredUnits != nil {
			t.Fatalf("%+v", b)
		}
	})
	t.Run("case_4_exact_1024_preferred_maximum", func(t *testing.T) {
		b, err := buildSizeOffer(1024, SizeProfilePreferredMaximum)
		if err != nil {
			t.Fatal(err)
		}
		if b.StandardCode == nil || *b.StandardCode != 0x0A {
			t.Fatalf("std=%v", b.StandardCode)
		}
		if b.PreferredUnits == nil || *b.PreferredUnits != 8 {
			t.Fatalf("pref=%v", b.PreferredUnits)
		}
	})
	t.Run("case_5_non_standard_1000", func(t *testing.T) {
		for _, profile := range []SizeProfile{SizeProfileRFC1006Compat, SizeProfilePreferredMaximum} {
			b, err := buildSizeOffer(1000, profile)
			if err != nil {
				t.Fatal(err)
			}
			if b.Offer.Preferred == nil || *b.Offer.Preferred != 896 {
				t.Fatalf("pref=%v", b.Offer.Preferred)
			}
			if b.Offer.Standard == nil || *b.Offer.Standard != 512 {
				t.Fatalf("std=%v", b.Offer.Standard)
			}
			if b.PreferredUnits == nil || *b.PreferredUnits != 7 {
				t.Fatalf("units=%v", b.PreferredUnits)
			}
			if b.StandardCode == nil || *b.StandardCode != 0x09 {
				t.Fatalf("code=%v", b.StandardCode)
			}
		}
	})
	t.Run("case_6_standard_16384", func(t *testing.T) {
		// 16384 is now a standard size (0x0E); RFC1006Compat takes the exact
		// standard code path, not the preferred+fallback path.
		b, err := buildSizeOffer(16384, SizeProfileRFC1006Compat)
		if err != nil {
			t.Fatal(err)
		}
		if b.StandardCode == nil || *b.StandardCode != 0x0E {
			t.Fatalf("code=%v", b.StandardCode)
		}
		if b.Offer.Standard == nil || *b.Offer.Standard != 16384 {
			t.Fatalf("std=%v", b.Offer.Standard)
		}
		if b.Offer.Preferred != nil {
			t.Fatalf("unexpected preferred=%v", b.Offer.Preferred)
		}
	})
	t.Run("case_7_maximum_65531", func(t *testing.T) {
		b, err := buildSizeOffer(65531, SizeProfileRFC1006Compat)
		if err != nil || !b.Offer.Omitted {
			t.Fatalf("%+v %v", b, err)
		}
		b, err = buildSizeOffer(65531, SizeProfilePreferredMaximum)
		if err != nil {
			t.Fatal(err)
		}
		if b.PreferredUnits == nil || *b.PreferredUnits != 511 || b.Offer.Preferred == nil || *b.Offer.Preferred != 65408 {
			t.Fatalf("%+v", b)
		}
		// fallbackStandard(65408) now returns 0x0F (32768); see case_1 comment.
		if b.StandardCode == nil || *b.StandardCode != 0x0F {
			t.Fatalf("fallback=%v", b.StandardCode)
		}
	})
	t.Run("case_8_configured_above_65531", func(t *testing.T) {
		_, err := buildSizeOffer(65532, SizeProfileRFC1006Compat)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestDecodeSizeOffer_DualPreserve(t *testing.T) {
	t.Run("case_9_neither", func(t *testing.T) {
		o, err := decodeSizeOffer(nil, nil)
		if err != nil || !o.Omitted {
			t.Fatalf("%+v %v", o, err)
		}
	})
	t.Run("case_10_c0_only", func(t *testing.T) {
		c := uint8(0x0A)
		o, err := decodeSizeOffer(&c, nil)
		if err != nil || o.Standard == nil || *o.Standard != 1024 || o.Preferred != nil {
			t.Fatalf("%+v %v", o, err)
		}
	})
	t.Run("case_11_f0_only", func(t *testing.T) {
		u := uint32(7)
		o, err := decodeSizeOffer(nil, &u)
		if err != nil || o.Preferred == nil || *o.Preferred != 896 || o.Standard != nil {
			t.Fatalf("%+v %v", o, err)
		}
	})
	t.Run("case_12_both_standard_le_preferred", func(t *testing.T) {
		c := uint8(0x09) // 512
		u := uint32(7)   // 896
		o, err := decodeSizeOffer(&c, &u)
		if err != nil || o.Standard == nil || *o.Standard != 512 || o.Preferred == nil || *o.Preferred != 896 {
			t.Fatalf("%+v %v", o, err)
		}
	})
	t.Run("case_13_both_standard_gt_preferred_valid", func(t *testing.T) {
		c := uint8(0x0B) // 2048
		u := uint32(7)   // 896
		o, err := decodeSizeOffer(&c, &u)
		if err != nil {
			t.Fatal(err)
		}
		if o.Standard == nil || *o.Standard != 2048 || o.Preferred == nil || *o.Preferred != 896 {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("case_14_invalid_preferred_zero", func(t *testing.T) {
		u := uint32(0)
		_, err := decodeSizeOffer(nil, &u)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_21_codec_units_above_511_ok_service_reject", func(t *testing.T) {
		// Generic codec accepts; service decodeSizeOffer rejects.
		u := uint32(512)
		_, err := decodeSizeOffer(nil, &u)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_22_units_above_511_itot_reject", func(t *testing.T) {
		u := uint32(512)
		_, err := decodeSizeOffer(nil, &u)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("undefined_code_0x11", func(t *testing.T) {
		c := uint8(0x11)
		_, err := decodeSizeOffer(&c, nil)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
}
