// SPDX-License-Identifier: MIT

package cotp

import (
	"strings"
	"testing"
)

func TestParameter_String(t *testing.T) {
	tests := []struct {
		p    Parameter
		want string
	}{
		{Parameter{Code: 0xC1, Value: nil}, "0xC1=[]"},
		{Parameter{Code: 0xC1, Value: []byte{}}, "0xC1=[]"},
		{Parameter{Code: 0xC1, Value: []byte{0x01, 0x02}}, "0xC1=0102"},
		{Parameter{Code: 0x99, Value: make([]byte, 20)}, "0x99=0000000000000000...(20)"},
	}
	for _, tt := range tests {
		got := tt.p.String()
		if got != tt.want {
			t.Errorf("Parameter%+v.String() = %q, want %q", tt.p, got, tt.want)
		}
	}
}

func TestCR_String(t *testing.T) {
	if got := (*CR)(nil).String(); got != "CR(nil)" {
		t.Errorf("CR(nil).String() = %q", got)
	}
	cr := &CR{CDT: 0, DestinationRef: 1, SourceRef: 2, ClassOption: 0}
	s := cr.String()
	if !strings.Contains(s, "CR{") || !strings.Contains(s, "DST:1") || !strings.Contains(s, "SRC:2") {
		t.Errorf("CR.String() = %q", s)
	}
	// Long selector to hit truncHex (> 8 bytes)
	cr.CallingSelector = make([]byte, 10)
	for i := range cr.CallingSelector {
		cr.CallingSelector[i] = byte(i)
	}
	s = cr.String()
	if !strings.Contains(s, "calling:") {
		t.Errorf("CR.String() with long selector = %q", s)
	}
	cr.Parameters = []Parameter{{Code: 0x99, Value: []byte{1}}}
	s = cr.String()
	if !strings.Contains(s, "params:1") {
		t.Errorf("CR.String() with params = %q", s)
	}
}

func TestCC_String(t *testing.T) {
	if got := (*CC)(nil).String(); got != "CC(nil)" {
		t.Errorf("CC(nil).String() = %q", got)
	}
	cc := &CC{DestinationRef: 1, SourceRef: 2}
	s := cc.String()
	if !strings.Contains(s, "CC{") || !strings.Contains(s, "DST:1") {
		t.Errorf("CC.String() = %q", s)
	}
	// Long selector to hit truncHex
	cc.CalledSelector = make([]byte, 10)
	s = cc.String()
	if !strings.Contains(s, "called:") {
		t.Errorf("CC.String() with long selector = %q", s)
	}
	cc.Parameters = []Parameter{{Code: 0x99, Value: []byte{1}}}
	s = cc.String()
	if !strings.Contains(s, "params:1") {
		t.Errorf("CC.String() with params = %q", s)
	}
}

func TestDT_String(t *testing.T) {
	if got := (*DT)(nil).String(); got != "DT(nil)" {
		t.Errorf("DT(nil).String() = %q", got)
	}
	dt := &DT{EOT: true, UserData: []byte{0xDE, 0xAD}}
	s := dt.String()
	if !strings.Contains(s, "DT{") || !strings.Contains(s, "EOT:true") || !strings.Contains(s, "userdata:2") {
		t.Errorf("DT.String() = %q", s)
	}
}

func TestDR_String(t *testing.T) {
	if got := (*DR)(nil).String(); got != "DR(nil)" {
		t.Errorf("DR(nil).String() = %q", got)
	}
	dr := &DR{DestinationRef: 1, SourceRef: 2, Reason: 3}
	s := dr.String()
	if !strings.Contains(s, "DR{") || !strings.Contains(s, "Reason:3") {
		t.Errorf("DR.String() = %q", s)
	}
	dr.Parameters = []Parameter{{Code: 0x99, Value: []byte{1}}}
	s = dr.String()
	if !strings.Contains(s, "params:1") {
		t.Errorf("DR.String() with params = %q", s)
	}
}

func TestDC_String(t *testing.T) {
	if got := (*DC)(nil).String(); got != "DC(nil)" {
		t.Errorf("DC(nil).String() = %q", got)
	}
	dc := &DC{DestinationRef: 1, SourceRef: 2}
	s := dc.String()
	if !strings.Contains(s, "DC{") {
		t.Errorf("DC.String() = %q", s)
	}
	dc.Parameters = []Parameter{{Code: 0x99, Value: []byte{1}}}
	s = dc.String()
	if !strings.Contains(s, "params:1") {
		t.Errorf("DC.String() with params = %q", s)
	}
}

func TestER_String(t *testing.T) {
	if got := (*ER)(nil).String(); got != "ER(nil)" {
		t.Errorf("ER(nil).String() = %q", got)
	}
	er := &ER{DestinationRef: 1, RejectCause: 2}
	s := er.String()
	if !strings.Contains(s, "ER{") || !strings.Contains(s, "Cause:2") {
		t.Errorf("ER.String() = %q", s)
	}
	er.Parameters = []Parameter{{Code: 0x99, Value: []byte{1}}}
	s = er.String()
	if !strings.Contains(s, "params:1") {
		t.Errorf("ER.String() with params = %q", s)
	}
}

func TestED_String(t *testing.T) {
	if got := (*ED)(nil).String(); got != "ED(nil)" {
		t.Errorf("ED(nil).String() = %q", got)
	}
	dst := uint16(1)
	nr := uint8(2)
	ed := &ED{DestinationRef: &dst, TPDUNR: &nr, EOT: true, UserData: []byte{0x01}}
	s := ed.String()
	if !strings.Contains(s, "ED{") || !strings.Contains(s, "EOT:true") || !strings.Contains(s, "userdata:1") {
		t.Errorf("ED.String() = %q", s)
	}
}

func TestAK_String(t *testing.T) {
	if got := (*AK)(nil).String(); got != "AK(nil)" {
		t.Errorf("AK(nil).String() = %q", got)
	}
	ak := &AK{CDT: 1, DestinationRef: 2, YRTUNR: 3}
	s := ak.String()
	if !strings.Contains(s, "AK{") || !strings.Contains(s, "YRTUNR:3") {
		t.Errorf("AK.String() = %q", s)
	}
}

func TestEA_String(t *testing.T) {
	if got := (*EA)(nil).String(); got != "EA(nil)" {
		t.Errorf("EA(nil).String() = %q", got)
	}
	ea := &EA{DestinationRef: 1, YREDTUNR: 2}
	s := ea.String()
	if !strings.Contains(s, "EA{") || !strings.Contains(s, "YREDTUNR:2") {
		t.Errorf("EA.String() = %q", s)
	}
}

func TestRJ_String(t *testing.T) {
	if got := (*RJ)(nil).String(); got != "RJ(nil)" {
		t.Errorf("RJ(nil).String() = %q", got)
	}
	rj := &RJ{CDT: 1, DestinationRef: 2, YRTUNR: 3}
	s := rj.String()
	if !strings.Contains(s, "RJ{") || !strings.Contains(s, "YRTUNR:3") {
		t.Errorf("RJ.String() = %q", s)
	}
}
