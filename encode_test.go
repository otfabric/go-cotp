// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"errors"
	"testing"
)

func TestMarshalBinary_NilReceiver(t *testing.T) {
	// MarshalBinary on nil receiver must return ErrNilReceiver, not ErrTooShort or panic.
	var cr *CR
	_, err := cr.MarshalBinary()
	if err == nil {
		t.Fatal("expected error for nil CR")
	}
	if !errors.Is(err, ErrNilReceiver) {
		t.Errorf("err = %v, want ErrNilReceiver", err)
	}
	var dt *DT
	_, err = dt.MarshalBinary()
	if err == nil {
		t.Fatal("expected error for nil DT")
	}
	if !errors.Is(err, ErrNilReceiver) {
		t.Errorf("err = %v, want ErrNilReceiver", err)
	}
}

func TestCR_MarshalBinary_RoundTrip(t *testing.T) {
	// Decode minimal CR, re-encode, must match
	cr, err := DecodeCR(minimalCR)
	if err != nil {
		t.Fatalf("DecodeCR: %v", err)
	}
	out, err := cr.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(out, minimalCR) {
		t.Errorf("round-trip:\n got %x\nwant %x", out, minimalCR)
	}
}

func TestCR_MarshalBinary_WithParams(t *testing.T) {
	cr := &CR{
		CDT:             0,
		DestinationRef:  0,
		SourceRef:       1,
		ClassOption:     0,
		CallingSelector: []byte{0x01, 0x02},
		CalledSelector:  []byte{0x03},
		TPDUSize:        bytePtr(0x07),
	}
	out, err := cr.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	cr2, err := DecodeCR(out)
	if err != nil {
		t.Fatalf("DecodeCR: %v", err)
	}
	if !bytes.Equal(cr2.CallingSelector, cr.CallingSelector) || !bytes.Equal(cr2.CalledSelector, cr.CalledSelector) {
		t.Errorf("selectors: got %v %v", cr2.CallingSelector, cr2.CalledSelector)
	}
	if cr2.TPDUSize == nil || *cr2.TPDUSize != *cr.TPDUSize {
		t.Errorf("TPDUSize: got %v", cr2.TPDUSize)
	}
}

func TestCR_MarshalBinary_Deterministic(t *testing.T) {
	cr := &CR{
		CDT:            0,
		DestinationRef: 0,
		SourceRef:      0,
		ClassOption:    0,
	}
	out1, _ := cr.MarshalBinary()
	out2, _ := cr.MarshalBinary()
	if !bytes.Equal(out1, out2) {
		t.Errorf("deterministic: %x != %x", out1, out2)
	}
}

func TestCC_MarshalBinary_RoundTrip(t *testing.T) {
	cc, err := DecodeCC(minimalCC)
	if err != nil {
		t.Fatalf("DecodeCC: %v", err)
	}
	out, err := cc.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(out, minimalCC) {
		t.Errorf("round-trip:\n got %x\nwant %x", out, minimalCC)
	}
}

func TestCC_MarshalBinary_Deterministic(t *testing.T) {
	cc := &CC{
		CDT:            0,
		DestinationRef: 1,
		SourceRef:      2,
		ClassOption:    0,
	}
	out1, _ := cc.MarshalBinary()
	out2, _ := cc.MarshalBinary()
	if !bytes.Equal(out1, out2) {
		t.Errorf("deterministic: %x != %x", out1, out2)
	}
}

func TestCC_MarshalBinary_WithUnknownParam(t *testing.T) {
	cc := &CC{
		CDT:            0,
		DestinationRef: 0,
		SourceRef:      0,
		ClassOption:    0,
		Parameters:     []Parameter{{Code: 0x99, Value: []byte{0xAA, 0xBB}}},
	}
	out, err := cc.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	cc2, err := DecodeCC(out)
	if err != nil {
		t.Fatalf("DecodeCC: %v", err)
	}
	if len(cc2.Parameters) != 1 || cc2.Parameters[0].Code != 0x99 || !bytes.Equal(cc2.Parameters[0].Value, []byte{0xAA, 0xBB}) {
		t.Errorf("Parameters = %v", cc2.Parameters)
	}
}

func TestCC_MarshalBinary_ParamValueTooLong(t *testing.T) {
	cc := &CC{
		CDT:            0,
		DestinationRef: 0,
		SourceRef:      0,
		ClassOption:    0,
		Parameters:     []Parameter{{Code: 0x99, Value: make([]byte, 256)}},
	}
	_, err := cc.MarshalBinary()
	if err == nil {
		t.Fatal("expected error for param value length 256")
	}
	if !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Errorf("err = %v", err)
	}
}

func bytePtr(b byte) *byte { return &b }
