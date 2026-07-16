// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"errors"
	"testing"
)

func TestHeaderBounds_LIShorterThanFixedPart(t *testing.T) {
	// Buffer long enough for CR fixed part, but LI claims only 5 header octets after LI.
	b := []byte{0x05, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := DecodeCR(b)
	if !errors.Is(err, ErrInvalidLI) {
		t.Fatalf("DecodeCR undersized LI: got %v, want ErrInvalidLI", err)
	}
	_, err = DecodeCC([]byte{0x05, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00})
	if !errors.Is(err, ErrInvalidLI) {
		t.Fatalf("DecodeCC undersized LI: got %v, want ErrInvalidLI", err)
	}
	// RJ: LI=3 cannot contain 4-octet fixed part.
	_, err = DecodeRJ([]byte{0x03, 0x50, 0x00, 0x00, 0x00})
	if !errors.Is(err, ErrInvalidLI) {
		t.Fatalf("DecodeRJ undersized LI: got %v, want ErrInvalidLI", err)
	}
}

func TestCRCC_SelectorEncodeTooLong(t *testing.T) {
	long := make([]byte, MaxParameterValueLength+1)
	cr := &CR{CallingSelector: long}
	_, err := cr.MarshalBinary()
	if !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Fatalf("CR calling selector: got %v, want ErrUnexpectedParameterLength", err)
	}
	cc := &CC{CalledSelector: long}
	_, err = cc.MarshalBinary()
	if !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Fatalf("CC called selector: got %v, want ErrUnexpectedParameterLength", err)
	}
}

func TestLooksLikeDT_MatchesPeekTypeMask(t *testing.T) {
	ok := []byte{0x02, 0xF0, 0x00}
	roa := []byte{0x02, 0xF1, 0x00}
	bad := []byte{0x02, 0xFF, 0x00}
	if !LooksLikeDT(ok) || !LooksLikeDT(roa) {
		t.Fatal("LooksLikeDT should accept 0xF0 and 0xF1")
	}
	if LooksLikeDT(bad) {
		t.Fatal("LooksLikeDT must reject 0xFF (aligned with PeekType)")
	}
	if _, err := PeekType(bad); !errors.Is(err, ErrInvalidTPDUCode) {
		t.Fatalf("PeekType(0xFF): got %v, want ErrInvalidTPDUCode", err)
	}
	if _, err := DecodeDT(bad); !errors.Is(err, ErrInvalidTPDUCode) {
		t.Fatalf("DecodeDT(0xFF): got %v, want ErrInvalidTPDUCode", err)
	}
}

func TestCRCC_UserDataRoundTrip(t *testing.T) {
	cr := &CR{
		SourceRef: 1,
		UserData:  []byte{0xDE, 0xAD},
	}
	out, err := cr.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	got, err := DecodeCR(out)
	if err != nil {
		t.Fatalf("DecodeCR: %v", err)
	}
	if !bytes.Equal(got.UserData, cr.UserData) {
		t.Fatalf("UserData = %x, want %x", got.UserData, cr.UserData)
	}

	cc := &CC{
		DestinationRef: 1,
		SourceRef:      2,
		UserData:       []byte{0xBE, 0xEF},
	}
	out, err = cc.MarshalBinary()
	if err != nil {
		t.Fatalf("CC MarshalBinary: %v", err)
	}
	gotCC, err := DecodeCC(out)
	if err != nil {
		t.Fatalf("DecodeCC: %v", err)
	}
	if !bytes.Equal(gotCC.UserData, cc.UserData) {
		t.Fatalf("CC UserData = %x, want %x", gotCC.UserData, cc.UserData)
	}
}

func TestCR_MaxLength128(t *testing.T) {
	// Header = 7 (LI+fixed), remaining user data max = 128-7 = 121.
	cr := &CR{UserData: make([]byte, MaxCRTPDULength-7)}
	out, err := cr.MarshalBinary()
	if err != nil {
		t.Fatalf("max-length CR: %v", err)
	}
	if len(out) != MaxCRTPDULength {
		t.Fatalf("len = %d, want %d", len(out), MaxCRTPDULength)
	}
	cr.UserData = make([]byte, MaxCRTPDULength-6) // one over
	_, err = cr.MarshalBinary()
	if !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("oversized CR encode: got %v, want ErrLengthMismatch", err)
	}
	oversized := make([]byte, MaxCRTPDULength+1)
	copy(oversized, minimalCR)
	oversized[0] = 0x06
	_, err = DecodeCR(oversized)
	if !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("oversized CR decode: got %v, want ErrLengthMismatch", err)
	}
}

func TestCRCC_DuplicateKnownParameterLastWins(t *testing.T) {
	// Two 0xC1 values; last (0x02) must win per X.224 13.2.3.
	b := []byte{0x0C, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 1, 0x01, 0xC1, 1, 0x02}
	cr, err := DecodeCR(b)
	if err != nil {
		t.Fatalf("DecodeCR: %v", err)
	}
	if len(cr.CallingSelector) != 1 || cr.CallingSelector[0] != 0x02 {
		t.Fatalf("CallingSelector = %v, want [0x02]", cr.CallingSelector)
	}
}
