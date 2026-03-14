package cotp

import (
	"testing"
)

func TestLooksLikeCR(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"minimal CR", minimalCR, true},
		{"minimal CC", minimalCC, false},
		{"minimal DT", minimalDT, false},
		{"minimal DR", minimalDR, false},
		{"short buffer", []byte{0x06, 0xE0}, false},
		{"bad LI", []byte{0xFF, 0xE0}, false},
		{"wrong type mask", []byte{0x06, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00}, false},
		{"empty", []byte{}, false},
		{"single byte", []byte{0x00}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeCR(tt.b)
			if got != tt.want {
				t.Errorf("LooksLikeCR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikeCC(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"minimal CC", minimalCC, true},
		{"minimal CR", minimalCR, false},
		{"minimal DT", minimalDT, false},
		{"minimal DR", minimalDR, false},
		{"minimal DC", minimalDC, false},
		{"short buffer", []byte{0x06, 0xD0}, false},
		{"bad LI", []byte{0xFF, 0xD0}, false},
		{"empty", []byte{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeCC(tt.b)
			if got != tt.want {
				t.Errorf("LooksLikeCC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikeDR(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"minimal DR", minimalDR, true},
		{"minimal CR", minimalCR, false},
		{"minimal DC", minimalDC, false},
		{"minimal ER", minimalER, false},
		{"short buffer", []byte{0x06, 0x80}, false},
		{"bad LI", []byte{0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00}, false},
		{"wrong type", []byte{0x06, 0xC0, 0x00, 0x01, 0x00, 0x02, 0x00}, false},
		{"empty", []byte{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeDR(tt.b)
			if got != tt.want {
				t.Errorf("LooksLikeDR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikeDC(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"minimal DC", minimalDC, true},
		{"minimal DR", minimalDR, false},
		{"minimal CR", minimalCR, false},
		{"short buffer", []byte{0x05, 0xC0}, false},
		{"wrong type", []byte{0x05, 0x80, 0x00, 0x01, 0x00, 0x02}, false},
		{"empty", []byte{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeDC(tt.b)
			if got != tt.want {
				t.Errorf("LooksLikeDC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikeDT(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"minimal DT", minimalDT, true},
		{"minimal CR", minimalCR, false},
		{"minimal CC", minimalCC, false},
		{"minimal DR", minimalDR, false},
		{"short buffer", []byte{0x02, 0xF0}, false},
		{"bad LI", []byte{0xFF, 0xF0, 0x00}, false},
		{"type 0xF0 mask", []byte{0x02, 0xF0, 0x00}, true},
		{"type 0xFF mask", []byte{0x02, 0xFF, 0x00}, true},
		{"empty", []byte{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeDT(tt.b)
			if got != tt.want {
				t.Errorf("LooksLikeDT() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikeER(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"minimal ER", minimalER, true},
		{"minimal DR", minimalDR, false},
		{"minimal DC", minimalDC, false},
		{"short buffer", []byte{0x04, 0x70}, false},
		{"wrong type", []byte{0x04, 0x80, 0x00, 0x01, 0x02}, false},
		{"empty", []byte{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeER(tt.b)
			if got != tt.want {
				t.Errorf("LooksLikeER() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsConnectionOriented(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"CR", minimalCR, true},
		{"CC", minimalCC, true},
		{"DR", minimalDR, true},
		{"DC", minimalDC, true},
		{"DT", minimalDT, false},
		{"ER", minimalER, false},
		{"short", []byte{0x01}, false},
		{"empty", []byte{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsConnectionOriented(tt.b)
			if got != tt.want {
				t.Errorf("IsConnectionOriented() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikeED(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"minimal ED", minimalED, true},
		{"CR", minimalCR, false},
		{"DT", minimalDT, false},
		{"short", []byte{0x04, 0x10}, false},
		{"bad LI", []byte{0xFF, 0x10, 0x00, 0x00, 0x00}, false},
		{"empty", []byte{}, false},
		{"type 0x11 not ED", []byte{0x04, 0x11, 0x00, 0x00, 0x00}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeED(tt.b)
			if got != tt.want {
				t.Errorf("LooksLikeED() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikeAK(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"minimal AK", minimalAK, true},
		{"CR", minimalCR, false},
		{"EA", minimalEA, false},
		{"RJ", minimalRJ, false},
		{"short", []byte{0x04, 0x60}, false},
		{"empty", []byte{}, false},
		{"0x60 mask", []byte{0x04, 0x60, 0x00, 0x00, 0x00}, true},
		{"0x6F mask", []byte{0x04, 0x6F, 0x00, 0x00, 0x00}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeAK(tt.b)
			if got != tt.want {
				t.Errorf("LooksLikeAK() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikeEA(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"minimal EA", minimalEA, true},
		{"ED", minimalED, false},
		{"AK", minimalAK, false},
		{"short", []byte{0x04, 0x20}, false},
		{"empty", []byte{}, false},
		{"type 0x21 not EA", []byte{0x04, 0x21, 0x00, 0x00, 0x00}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeEA(tt.b)
			if got != tt.want {
				t.Errorf("LooksLikeEA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikeRJ(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"minimal RJ", minimalRJ, true},
		{"AK", minimalAK, false},
		{"EA", minimalEA, false},
		{"short", []byte{0x04, 0x50}, false},
		{"empty", []byte{}, false},
		{"0x50 mask", []byte{0x04, 0x50, 0x00, 0x00, 0x00}, true},
		{"0x5F mask", []byte{0x04, 0x5F, 0x00, 0x00, 0x00}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeRJ(tt.b)
			if got != tt.want {
				t.Errorf("LooksLikeRJ() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAckType(t *testing.T) {
	tests := []struct {
		name string
		t    TPDUType
		want bool
	}{
		{"AK", TypeAK, true},
		{"RJ", TypeRJ, true},
		{"CR", TypeCR, false},
		{"CC", TypeCC, false},
		{"DT", TypeDT, false},
		{"ED", TypeED, false},
		{"EA", TypeEA, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAckType(tt.t)
			if got != tt.want {
				t.Errorf("IsAckType(%s) = %v, want %v", tt.t, got, tt.want)
			}
		})
	}
}
