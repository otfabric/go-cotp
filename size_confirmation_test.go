// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"testing"
)

func TestInterpretCCSize(t *testing.T) {
	sentBoth := bothOffer(512, 896)

	t.Run("case_15_peer_returns_fallback_c0", func(t *testing.T) {
		c := uint8(0x09) // 512
		got, err := interpretCCSize(sentBoth, &c, nil, SizeProfileRFC1006Compat)
		if err != nil || got != 512 {
			t.Fatalf("%d %v", got, err)
		}
	})
	t.Run("case_16_peer_honors_f0", func(t *testing.T) {
		u := uint32(7)
		got, err := interpretCCSize(sentBoth, nil, &u, SizeProfilePreferredMaximum)
		if err != nil || got != 896 {
			t.Fatalf("%d %v", got, err)
		}
	})
	t.Run("case_17a_compat_cc_omission", func(t *testing.T) {
		sent := bothOffer(2048, 16384)
		got, err := interpretCCSize(sent, nil, nil, SizeProfileRFC1006Compat)
		if err != nil || got != 16384 {
			t.Fatalf("%d %v", got, err)
		}
	})
	t.Run("case_17b_preferred_maximum_cc_omission", func(t *testing.T) {
		_, err := interpretCCSize(sentBoth, nil, nil, SizeProfilePreferredMaximum)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_43_cc_f0_exceeds_offer", func(t *testing.T) {
		u := uint32(8) // 1024 > 896
		_, err := interpretCCSize(sentBoth, nil, &u, SizeProfilePreferredMaximum)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_44_cc_c0_exceeds_fallback", func(t *testing.T) {
		c := uint8(0x0A) // 1024 > 512
		_, err := interpretCCSize(sentBoth, &c, nil, SizeProfileRFC1006Compat)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_45_cr_c0_only_cc_f0", func(t *testing.T) {
		u := uint32(8)
		_, err := interpretCCSize(stdOffer(1024), nil, &u, SizeProfileRFC1006Compat)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_46_cr_f0_only_cc_c0", func(t *testing.T) {
		c := uint8(0x0A)
		_, err := interpretCCSize(prefOffer(1024), &c, nil, SizeProfilePreferredMaximum)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("both_params_malformed", func(t *testing.T) {
		c := uint8(0x09)
		u := uint32(7)
		_, err := interpretCCSize(sentBoth, &c, &u, SizeProfileRFC1006Compat)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("compat_omission_caps_at_local_proposal", func(t *testing.T) {
		// Client offered preferred 16384; omission must not become 65531.
		sent, err := buildSizeOffer(16384, SizeProfileRFC1006Compat)
		if err != nil {
			t.Fatal(err)
		}
		got, err := interpretCCSize(sent.Offer, nil, nil, SizeProfileRFC1006Compat)
		if err != nil || got != 16384 {
			t.Fatalf("%d %v", got, err)
		}
	})
}
