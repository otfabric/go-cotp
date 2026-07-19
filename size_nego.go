// SPDX-License-Identifier: MIT

package cotp

import (
	"fmt"
)

// Class 0 standard TPDU sizes (X.224 §13.3.4 b).
// The original X.224:1988 spec defined codes 0x07–0x0B for class 0, but
// RFC 1006 and its successors (including IEC 61850-8-1 MMS stacks such as
// libIEC61850 and iec61850bean) routinely negotiate 0x0C–0x10 in class 0
// connections. Rejecting these codes prevents interoperability with conformant
// implementations, so we accept the full range up to 65536 bytes (0x10).
var class0StandardSizes = []struct {
	code uint8
	size int
}{
	{0x10, 65536},
	{0x0F, 32768},
	{0x0E, 16384},
	{0x0D, 8192},
	{0x0C, 4096},
	{0x0B, 2048},
	{0x0A, 1024},
	{0x09, 512},
	{0x08, 256},
	{0x07, 128},
}

type sizePath uint8

const (
	sizePathOmitted sizePath = iota
	sizePathStandard
	sizePathPreferred
)

type sizeOffer struct {
	Standard  *int
	Preferred *int
	Omitted   bool
}

type sizeSelection struct {
	Path           sizePath
	Effective      int
	StandardCode   *uint8
	PreferredUnits *uint32
}

type sizeCRBuild struct {
	Offer          sizeOffer
	StandardCode   *uint8
	PreferredUnits *uint32
}

func normalizeConfiguredMax(configured int) (int, error) {
	if configured == 0 {
		return DefaultMaxTPDULength, nil
	}
	if configured < MinTPDULength || configured > MaxITOTTPDULength {
		return 0, fmt.Errorf("MaxTPDULength %d: %w", configured, ErrInvalidConfig)
	}
	return configured, nil
}

func preferredUnitsAndEffective(configured int) (units uint32, effective int, err error) {
	ceiling, err := normalizeConfiguredMax(configured)
	if err != nil {
		return 0, 0, err
	}
	u := ceiling / 128
	if u < 1 {
		return 0, 0, fmt.Errorf("preferred units for %d: %w", ceiling, ErrInvalidConfig)
	}
	if u > MaxPreferredUnitsITOT {
		u = MaxPreferredUnitsITOT
	}
	units = uint32(u)
	effective = int(units) * 128
	return units, effective, nil
}

func class0StandardCode(size int) (uint8, bool) {
	for _, e := range class0StandardSizes {
		if e.size == size {
			return e.code, true
		}
	}
	return 0, false
}

func class0StandardSize(code uint8) (int, bool) {
	for _, e := range class0StandardSizes {
		if e.code == code {
			return e.size, true
		}
	}
	return 0, false
}

func fallbackStandard(preferredEffective int) (size int, code uint8, err error) {
	if preferredEffective < MinTPDULength {
		return 0, 0, fmt.Errorf("fallback for preferred %d: %w", preferredEffective, ErrInvalidConfig)
	}
	for _, e := range class0StandardSizes {
		if e.size <= preferredEffective {
			return e.size, e.code, nil
		}
	}
	return 0, 0, fmt.Errorf("fallback for preferred %d: %w", preferredEffective, ErrInvalidConfig)
}

func normalizePreferredCeiling(ceiling int) (int, error) {
	_, effective, err := preferredUnitsAndEffective(ceiling)
	return effective, err
}

func normalizeStandardCeiling(ceiling int) (int, uint8, error) {
	c, err := normalizeConfiguredMax(ceiling)
	if err != nil {
		return 0, 0, err
	}
	size, code, err := fallbackStandard(c)
	return size, code, err
}

func buildSizeOffer(configured int, profile SizeProfile) (sizeCRBuild, error) {
	if profile != SizeProfileRFC1006Compat && profile != SizeProfilePreferredMaximum {
		return sizeCRBuild{}, fmt.Errorf("SizeProfile %d: %w", profile, ErrInvalidConfig)
	}
	ceiling, err := normalizeConfiguredMax(configured)
	if err != nil {
		return sizeCRBuild{}, err
	}

	switch profile {
	case SizeProfileRFC1006Compat:
		if ceiling == DefaultMaxTPDULength {
			return sizeCRBuild{Offer: sizeOffer{Omitted: true}}, nil
		}
		if code, ok := class0StandardCode(ceiling); ok {
			c := code
			s := ceiling
			return sizeCRBuild{
				Offer:        sizeOffer{Standard: &s},
				StandardCode: &c,
			}, nil
		}
		units, effective, err := preferredUnitsAndEffective(ceiling)
		if err != nil {
			return sizeCRBuild{}, err
		}
		fbSize, fbCode, err := fallbackStandard(effective)
		if err != nil {
			return sizeCRBuild{}, err
		}
		u := units
		c := fbCode
		pref := effective
		std := fbSize
		return sizeCRBuild{
			Offer:          sizeOffer{Standard: &std, Preferred: &pref},
			StandardCode:   &c,
			PreferredUnits: &u,
		}, nil

	case SizeProfilePreferredMaximum:
		units, effective, err := preferredUnitsAndEffective(ceiling)
		if err != nil {
			return sizeCRBuild{}, err
		}
		u := units
		pref := effective
		if code, ok := class0StandardCode(ceiling); ok && ceiling == effective {
			c := code
			std := ceiling
			return sizeCRBuild{
				Offer:          sizeOffer{Standard: &std, Preferred: &pref},
				StandardCode:   &c,
				PreferredUnits: &u,
			}, nil
		}
		fbSize, fbCode, err := fallbackStandard(effective)
		if err != nil {
			return sizeCRBuild{}, err
		}
		c := fbCode
		std := fbSize
		return sizeCRBuild{
			Offer:          sizeOffer{Standard: &std, Preferred: &pref},
			StandardCode:   &c,
			PreferredUnits: &u,
		}, nil
	}
	return sizeCRBuild{}, fmt.Errorf("SizeProfile %d: %w", profile, ErrInvalidConfig)
}

func decodeSizeOffer(standardCode *uint8, preferredUnits *uint32) (sizeOffer, error) {
	if standardCode == nil && preferredUnits == nil {
		return sizeOffer{Omitted: true}, nil
	}
	var offer sizeOffer
	if standardCode != nil {
		size, ok := class0StandardSize(*standardCode)
		if !ok {
			return sizeOffer{}, fmt.Errorf("TPDU size code 0x%02x not allowed in class 0: %w", *standardCode, ErrHandshake)
		}
		s := size
		offer.Standard = &s
	}
	if preferredUnits != nil {
		if *preferredUnits == 0 || *preferredUnits > MaxPreferredUnitsITOT {
			return sizeOffer{}, fmt.Errorf("preferred units %d: %w", *preferredUnits, ErrHandshake)
		}
		eff := int(*preferredUnits) * 128
		offer.Preferred = &eff
	}
	return offer, nil
}

func selectSize(peer sizeOffer, serverCeiling int, callbackCeiling int, profile SizeProfile) (sizeSelection, error) {
	if profile != SizeProfileRFC1006Compat && profile != SizeProfilePreferredMaximum {
		return sizeSelection{}, fmt.Errorf("SizeProfile %d: %w", profile, ErrInvalidConfig)
	}
	serverNorm, err := normalizeConfiguredMax(serverCeiling)
	if err != nil {
		return sizeSelection{}, err
	}
	if callbackCeiling != 0 {
		if _, err := normalizeConfiguredMax(callbackCeiling); err != nil {
			return sizeSelection{}, err
		}
	}

	// Omitted peer CR: legacy / standard path only (never invent 0xF0).
	if peer.Omitted || (peer.Standard == nil && peer.Preferred == nil) {
		return selectOmittedCR(serverNorm, callbackCeiling, profile)
	}

	if peer.Preferred != nil {
		return selectPreferredPath(*peer.Preferred, serverNorm, callbackCeiling)
	}
	if peer.Standard != nil {
		return selectStandardPath(*peer.Standard, serverNorm, callbackCeiling)
	}
	return sizeSelection{}, fmt.Errorf("empty size offer: %w", ErrHandshake)
}

func selectOmittedCR(serverCeiling int, callbackCeiling int, profile SizeProfile) (sizeSelection, error) {
	_ = profile // PreferredMaximum still uses legacy/standard response for omitted CR.
	ceiling := serverCeiling
	if callbackCeiling != 0 {
		if callbackCeiling < ceiling {
			ceiling = callbackCeiling
		}
	}
	if ceiling == DefaultMaxTPDULength {
		return sizeSelection{Path: sizePathOmitted, Effective: DefaultMaxTPDULength}, nil
	}
	if code, ok := class0StandardCode(ceiling); ok {
		c := code
		return sizeSelection{Path: sizePathStandard, Effective: ceiling, StandardCode: &c}, nil
	}
	size, code, err := normalizeStandardCeiling(ceiling)
	if err != nil {
		return sizeSelection{}, err
	}
	c := code
	return sizeSelection{Path: sizePathStandard, Effective: size, StandardCode: &c}, nil
}

func selectPreferredPath(peerPreferred, serverCeiling, callbackCeiling int) (sizeSelection, error) {
	serverEff, err := normalizePreferredCeiling(serverCeiling)
	if err != nil {
		return sizeSelection{}, err
	}
	selected := peerPreferred
	if serverEff < selected {
		selected = serverEff
	}
	if callbackCeiling != 0 {
		cbEff, err := normalizePreferredCeiling(callbackCeiling)
		if err != nil {
			return sizeSelection{}, err
		}
		if cbEff < selected {
			selected = cbEff
		}
	}
	if selected < MinTPDULength {
		return sizeSelection{}, fmt.Errorf("selected preferred %d: %w", selected, ErrHandshake)
	}
	units := uint32(selected / 128)
	if units == 0 || units > MaxPreferredUnitsITOT {
		return sizeSelection{}, fmt.Errorf("selected preferred units %d: %w", units, ErrHandshake)
	}
	selected = int(units) * 128
	u := units
	return sizeSelection{Path: sizePathPreferred, Effective: selected, PreferredUnits: &u}, nil
}

func selectStandardPath(peerStandard, serverCeiling, callbackCeiling int) (sizeSelection, error) {
	serverSize, serverCode, err := normalizeStandardCeiling(serverCeiling)
	if err != nil {
		return sizeSelection{}, err
	}
	selected := peerStandard
	if serverSize < selected {
		selected = serverSize
	}
	if callbackCeiling != 0 {
		cbSize, _, err := normalizeStandardCeiling(callbackCeiling)
		if err != nil {
			return sizeSelection{}, err
		}
		if cbSize < selected {
			selected = cbSize
		}
	}
	code, ok := class0StandardCode(selected)
	if !ok {
		// selected may need to be floored to a standard if peer offered standard
		// but mins produced a non-standard intermediate — re-floor.
		size, c, err := fallbackStandard(selected)
		if err != nil {
			return sizeSelection{}, err
		}
		selected = size
		code = c
	}
	_ = serverCode
	c := code
	return sizeSelection{Path: sizePathStandard, Effective: selected, StandardCode: &c}, nil
}

func interpretCCSize(sent sizeOffer, ccStandardCode *uint8, ccPreferredUnits *uint32, profile SizeProfile) (int, error) {
	if profile != SizeProfileRFC1006Compat && profile != SizeProfilePreferredMaximum {
		return 0, fmt.Errorf("SizeProfile %d: %w", profile, ErrInvalidConfig)
	}
	if ccStandardCode != nil && ccPreferredUnits != nil {
		return 0, fmt.Errorf("CC contains both 0xC0 and 0xF0: %w", ErrHandshake)
	}

	if ccStandardCode == nil && ccPreferredUnits == nil {
		if profile == SizeProfilePreferredMaximum {
			return 0, fmt.Errorf("CC omits size under PreferredMaximum: %w", ErrHandshake)
		}
		// Compat omission: min(client effective proposal, 65531)
		local := clientEffectiveProposal(sent)
		if local > DefaultMaxTPDULength {
			local = DefaultMaxTPDULength
		}
		return local, nil
	}

	if ccPreferredUnits != nil {
		if sent.Preferred == nil {
			return 0, fmt.Errorf("CC selects 0xF0 but CR did not offer preferred: %w", ErrHandshake)
		}
		if *ccPreferredUnits == 0 || *ccPreferredUnits > MaxPreferredUnitsITOT {
			return 0, fmt.Errorf("CC preferred units %d: %w", *ccPreferredUnits, ErrHandshake)
		}
		eff := int(*ccPreferredUnits) * 128
		if eff > *sent.Preferred {
			return 0, fmt.Errorf("CC preferred %d exceeds offer %d: %w", eff, *sent.Preferred, ErrHandshake)
		}
		return eff, nil
	}

	// CC standard only
	if sent.Standard == nil && !sent.Omitted {
		return 0, fmt.Errorf("CC selects 0xC0 but CR did not offer standard: %w", ErrHandshake)
	}
	size, ok := class0StandardSize(*ccStandardCode)
	if !ok {
		return 0, fmt.Errorf("CC TPDU size code 0x%02x not allowed in class 0: %w", *ccStandardCode, ErrHandshake)
	}
	if sent.Omitted {
		// Compat omitted CR: peer may return an explicit selection. Accept sizes
		// up to the local proposal, capping rather than rejecting larger values
		// (e.g. iec61850bean sends 0x10 = 65536 while our local max is 65531).
		local := clientEffectiveProposal(sent)
		if size > local {
			size = local
		}
		return size, nil
	}
	if size > *sent.Standard {
		return 0, fmt.Errorf("CC standard %d exceeds offer %d: %w", size, *sent.Standard, ErrHandshake)
	}
	return size, nil
}

func clientEffectiveProposal(sent sizeOffer) int {
	if sent.Preferred != nil {
		return *sent.Preferred
	}
	if sent.Standard != nil {
		return *sent.Standard
	}
	return DefaultMaxTPDULength
}

func indicationMaxTPDULength(offer sizeOffer) int {
	return clientEffectiveProposal(offer)
}
