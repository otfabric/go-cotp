package cotp

import "testing"

func TestTPDUType_String(t *testing.T) {
	tests := []struct {
		t    TPDUType
		want string
	}{
		{TypeCR, "CR"},
		{TypeCC, "CC"},
		{TypeDR, "DR"},
		{TypeDC, "DC"},
		{TypeDT, "DT"},
		{TypeER, "ER"},
		{TypeED, "ED"},
		{TypeAK, "AK"},
		{TypeEA, "EA"},
		{TypeRJ, "RJ"},
		{0xFF, "unknown"},
		{0x00, "unknown"},
	}
	for _, tt := range tests {
		if got := tt.t.String(); got != tt.want {
			t.Errorf("TPDUType(%#02x).String() = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestConstants(t *testing.T) {
	if MinHeaderLength != 2 {
		t.Errorf("MinHeaderLength = %d, want 2", MinHeaderLength)
	}
	if MaxLI != 254 {
		t.Errorf("MaxLI = %d, want 254", MaxLI)
	}
}
