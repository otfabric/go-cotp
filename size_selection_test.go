// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"testing"
)

func prefOffer(n int) sizeOffer {
	p := n
	return sizeOffer{Preferred: &p}
}

func stdOffer(n int) sizeOffer {
	s := n
	return sizeOffer{Standard: &s}
}

func bothOffer(std, pref int) sizeOffer {
	s, p := std, pref
	return sizeOffer{Standard: &s, Preferred: &p}
}

func TestSelectSize_PathNormalized(t *testing.T) {
	t.Run("case_13_standard_gt_preferred_uses_preferred_path", func(t *testing.T) {
		sel, err := selectSize(bothOffer(2048, 896), 65531, 0, SizeProfilePreferredMaximum)
		if err != nil {
			t.Fatal(err)
		}
		if sel.Path != sizePathPreferred || sel.Effective != 896 || sel.PreferredUnits == nil || *sel.PreferredUnits != 7 {
			t.Fatalf("%+v", sel)
		}
		if sel.StandardCode != nil {
			t.Fatal("CC must not encode both")
		}
	})
	t.Run("case_18_callback_ceiling_lower", func(t *testing.T) {
		sel, err := selectSize(prefOffer(1024), 2048, 512, SizeProfilePreferredMaximum)
		if err != nil {
			t.Fatal(err)
		}
		if sel.Effective != 512 {
			t.Fatalf("got %d", sel.Effective)
		}
	})
	t.Run("case_19_callback_ceiling_higher_no_raise", func(t *testing.T) {
		sel, err := selectSize(prefOffer(1024), 1024, 2048, SizeProfilePreferredMaximum)
		if err != nil {
			t.Fatal(err)
		}
		if sel.Effective != 1024 {
			t.Fatalf("got %d", sel.Effective)
		}
	})
	t.Run("case_39_preferred_callback_ceiling_is_normalized", func(t *testing.T) {
		sel, err := selectSize(prefOffer(1024), 1024, 1000, SizeProfilePreferredMaximum)
		if err != nil {
			t.Fatal(err)
		}
		if sel.Path != sizePathPreferred || sel.Effective != 896 {
			t.Fatalf("%+v", sel)
		}
	})
	t.Run("case_40_standard_server_ceiling_normalized", func(t *testing.T) {
		sel, err := selectSize(stdOffer(1024), 1000, 0, SizeProfileRFC1006Compat)
		if err != nil {
			t.Fatal(err)
		}
		if sel.Path != sizePathStandard || sel.Effective != 512 {
			t.Fatalf("%+v", sel)
		}
	})
	t.Run("case_41_callback_129_preferred_path", func(t *testing.T) {
		sel, err := selectSize(prefOffer(1024), 2048, 129, SizeProfilePreferredMaximum)
		if err != nil {
			t.Fatal(err)
		}
		if sel.Effective != 128 {
			t.Fatalf("got %d", sel.Effective)
		}
	})
	t.Run("case_42_callback_129_standard_path", func(t *testing.T) {
		sel, err := selectSize(stdOffer(1024), 2048, 129, SizeProfileRFC1006Compat)
		if err != nil {
			t.Fatal(err)
		}
		if sel.Effective != 128 {
			t.Fatalf("got %d", sel.Effective)
		}
	})
	t.Run("case_47_omitted_cr_server_65531", func(t *testing.T) {
		sel, err := selectSize(sizeOffer{Omitted: true}, 65531, 0, SizeProfileRFC1006Compat)
		if err != nil {
			t.Fatal(err)
		}
		if sel.Path != sizePathOmitted || sel.Effective != 65531 || sel.StandardCode != nil || sel.PreferredUnits != nil {
			t.Fatalf("%+v", sel)
		}
	})
	t.Run("case_48_omitted_cr_server_1024", func(t *testing.T) {
		sel, err := selectSize(sizeOffer{Omitted: true}, 1024, 0, SizeProfileRFC1006Compat)
		if err != nil {
			t.Fatal(err)
		}
		if sel.Path != sizePathStandard || sel.Effective != 1024 || sel.StandardCode == nil || *sel.StandardCode != 0x0A {
			t.Fatalf("%+v", sel)
		}
		if sel.PreferredUnits != nil {
			t.Fatal("must not invent F0")
		}
	})
	t.Run("case_49_omitted_cr_server_1000", func(t *testing.T) {
		sel, err := selectSize(sizeOffer{Omitted: true}, 1000, 0, SizeProfileRFC1006Compat)
		if err != nil {
			t.Fatal(err)
		}
		if sel.Effective != 512 || sel.StandardCode == nil || *sel.StandardCode != 0x09 {
			t.Fatalf("%+v", sel)
		}
	})
	t.Run("case_50_omitted_cr_preferred_maximum_no_f0", func(t *testing.T) {
		sel, err := selectSize(sizeOffer{Omitted: true}, 1024, 0, SizeProfilePreferredMaximum)
		if err != nil {
			t.Fatal(err)
		}
		if sel.PreferredUnits != nil || sel.StandardCode == nil || *sel.StandardCode != 0x0A {
			t.Fatalf("%+v", sel)
		}
	})
	t.Run("invalid_profile", func(t *testing.T) {
		_, err := selectSize(stdOffer(1024), 1024, 0, SizeProfile(99))
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("err=%v", err)
		}
	})
}
