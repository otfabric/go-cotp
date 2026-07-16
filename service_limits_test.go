// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"testing"
)

func TestServiceLimits(t *testing.T) {
	t.Run("case_27_max_tsdu_negative", func(t *testing.T) {
		if err := validateMaxTSDULength(-1); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_28_write_tsdu_too_large_no_io", func(t *testing.T) {
		err := validateWriteTSDULength(100, 50)
		if !errors.Is(err, ErrTSDUTooLarge) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_29_reassembly_exceeds", func(t *testing.T) {
		err := validateReassemblyBound(DefaultMaxTSDULength+1, DefaultMaxTSDULength)
		if !errors.Is(err, ErrTSDUTooLarge) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("empty_tsdu", func(t *testing.T) {
		if err := validateWriteTSDULength(0, 100); !errors.Is(err, ErrEmptyTSDU) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_51_connect_data_32", func(t *testing.T) {
		if err := validateConnectDataLength(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("case_52_connect_data_33", func(t *testing.T) {
		if err := validateConnectDataLength(make([]byte, 33)); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_53_server_cc_connect_data_33", func(t *testing.T) {
		// Same preflight applies before CC write.
		if err := validateConnectDataLength(make([]byte, 33)); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("selector_too_long", func(t *testing.T) {
		if err := validateSelectorLength(make([]byte, 256), "calling"); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("cr_total_with_connect_data", func(t *testing.T) {
		cr := &CR{
			SourceRef:       1,
			UserData:        make([]byte, 32),
			CallingSelector: make([]byte, 80),
			CalledSelector:  make([]byte, 80),
		}
		_, err := cr.MarshalBinary()
		if err == nil {
			t.Fatal("expected CR length error")
		}
		if !errors.Is(err, ErrLengthMismatch) && !errors.Is(err, ErrInvalidLI) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("indication_max_prefers_preferred", func(t *testing.T) {
		o := bothOffer(512, 896)
		if got := indicationMaxTPDULength(o); got != 896 {
			t.Fatalf("got %d", got)
		}
	})
}
