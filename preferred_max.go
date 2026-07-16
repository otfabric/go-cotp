// SPDX-License-Identifier: MIT

package cotp

import (
	"fmt"
	"math"
)

// PreferredMaxTPDULength returns the effective TPDU length in octets for the
// given preferred-maximum wire units (units × 128).
//
// This is a generic X.224 codec helper: units == 0 is rejected; there is no
// RFC 1006/2126 (ITOT) 511-unit ceiling here.
func PreferredMaxTPDULength(units uint32) (uint64, error) {
	if units == 0 {
		return 0, fmt.Errorf("preferred max TPDU length: zero units: %w", ErrUnexpectedParameterLength)
	}
	return uint64(units) * 128, nil
}

// PreferredMaxTPDUUnits returns the exact preferred-maximum wire units for an
// effective octet length. The length must be a positive multiple of 128 and
// fit in a uint32 unit count. No flooring is performed.
func PreferredMaxTPDUUnits(length uint64) (uint32, error) {
	if length == 0 {
		return 0, fmt.Errorf("preferred max TPDU units: zero length: %w", ErrUnexpectedParameterLength)
	}
	if length%128 != 0 {
		return 0, fmt.Errorf("preferred max TPDU units: length %d not multiple of 128: %w", length, ErrUnexpectedParameterLength)
	}
	units := length / 128
	if units > math.MaxUint32 {
		return 0, fmt.Errorf("preferred max TPDU units: length %d overflows uint32 units: %w", length, ErrUnexpectedParameterLength)
	}
	return uint32(units), nil
}

// decodePreferredMaxUnits decodes a 1–4 octet big-endian preferred-maximum value.
// Leading zero octets are accepted. Zero units and invalid lengths are rejected.
func decodePreferredMaxUnits(value []byte) (uint32, error) {
	if len(value) < 1 || len(value) > 4 {
		return 0, fmt.Errorf("preferred max TPDU size: length %d: %w", len(value), ErrUnexpectedParameterLength)
	}
	var units uint32
	for _, b := range value {
		units = (units << 8) | uint32(b)
	}
	if units == 0 {
		return 0, fmt.Errorf("preferred max TPDU size: zero value: %w", ErrUnexpectedParameterLength)
	}
	return units, nil
}

// encodePreferredMaxUnits encodes units in the minimal big-endian form (1–4 octets).
func encodePreferredMaxUnits(units uint32) ([]byte, error) {
	if units == 0 {
		return nil, fmt.Errorf("preferred max TPDU size: zero units: %w", ErrUnexpectedParameterLength)
	}
	switch {
	case units <= 0xff:
		return []byte{byte(units)}, nil
	case units <= 0xffff:
		return []byte{byte(units >> 8), byte(units)}, nil
	case units <= 0xffffff:
		return []byte{byte(units >> 16), byte(units >> 8), byte(units)}, nil
	default:
		return []byte{byte(units >> 24), byte(units >> 16), byte(units >> 8), byte(units)}, nil
	}
}
