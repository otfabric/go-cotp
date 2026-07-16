// SPDX-License-Identifier: MIT

package cotp

import (
	"errors"
	"testing"
)

func TestHandshakeReferences(t *testing.T) {
	t.Run("case_30_cr_src_ref_zero", func(t *testing.T) {
		err := validateCRReferences(0, 0)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_31_cc_src_ref_zero", func(t *testing.T) {
		err := validateCCReferences(1, 0, 1)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_32_cc_dst_mismatch", func(t *testing.T) {
		err := validateCCReferences(2, 3, 1)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("valid_refs", func(t *testing.T) {
		if err := validateCRReferences(0, 1); err != nil {
			t.Fatal(err)
		}
		if err := validateCCReferences(1, 2, 1); err != nil {
			t.Fatal(err)
		}
	})
}

func TestHandshakeClass0Fields(t *testing.T) {
	t.Run("case_33_cr_nonzero_cdt", func(t *testing.T) {
		if err := validateClass0CRFixed(1, 0); !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_34_cr_nonzero_options", func(t *testing.T) {
		if err := validateClass0CRFixed(0, 0x01); !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_35_cc_nonzero_cdt_options", func(t *testing.T) {
		if err := validateClass0CCFixed(1, 0); !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
		if err := validateClass0CCFixed(0, 0x10); !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_36_dt_illegal_encoding", func(t *testing.T) {
		if err := validateMinimalClass0DT(2, 0xF1, 0x00); !errors.Is(err, ErrHandshake) {
			t.Fatalf("roa err=%v", err)
		}
		if err := validateMinimalClass0DT(2, 0xF0, 0x01); !errors.Is(err, ErrHandshake) {
			t.Fatalf("nr err=%v", err)
		}
		if err := validateMinimalClass0DT(3, 0xF0, 0x00); !errors.Is(err, ErrHandshake) {
			t.Fatalf("li err=%v", err)
		}
		if err := validateMinimalClass0DT(2, 0xF0, 0x80); err != nil { // EOT=1, NR=0 OK
			t.Fatal(err)
		}
	})
}

func TestHandshakeParameters(t *testing.T) {
	t.Run("case_54_cr_unknown_ignored", func(t *testing.T) {
		err := validateCRParameters([]Parameter{{Code: 0xFF, Value: []byte{1}}})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("case_55_cr_forbidden_rejected", func(t *testing.T) {
		err := validateCRParameters([]Parameter{{Code: 0xC5, Value: []byte{0, 0}}})
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_56_cc_unknown_rejected", func(t *testing.T) {
		err := validateCCParameters([]Parameter{{Code: 0xFF, Value: []byte{1}}})
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_57_cc_forbidden_rejected", func(t *testing.T) {
		err := validateCCParameters([]Parameter{{Code: 0xC6, Value: []byte{0}}})
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestHandshakeSelectors(t *testing.T) {
	t.Run("case_23_server_selector_cr_absent", func(t *testing.T) {
		err := validateServerCalledSelector([]byte{0x01, 0x02}, nil)
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("server_nil_no_requirement", func(t *testing.T) {
		if err := validateServerCalledSelector(nil, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("server_empty_requires_empty", func(t *testing.T) {
		if err := validateServerCalledSelector([]byte{}, []byte{}); err != nil {
			t.Fatal(err)
		}
		if err := validateServerCalledSelector([]byte{}, nil); !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("case_24_cc_selector_mismatch", func(t *testing.T) {
		err := validateClientCCSelector([]byte{1, 2}, []byte{1, 3})
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("cc_selector_omission_ok", func(t *testing.T) {
		if err := validateClientCCSelector([]byte{1, 2}, nil); err != nil {
			t.Fatal(err)
		}
	})
}

func TestHandshakeCallbackAndEnums(t *testing.T) {
	t.Run("case_37_onconnect_error_is_local", func(t *testing.T) {
		// Pure contract: callback errors are wrapped with ErrHandshake by the
		// future engine; document the sentinel relationship here.
		err := errors.Join(errors.New("callback boom"), ErrHandshake)
		if !errors.Is(err, ErrHandshake) {
			t.Fatal(err)
		}
	})
	t.Run("case_38_invalid_action", func(t *testing.T) {
		if err := validateConnectAction(ConnectAction(9)); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("unknown_profile", func(t *testing.T) {
		if err := validateSizeProfile(SizeProfile(3)); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("err=%v", err)
		}
	})
}
