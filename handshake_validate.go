// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"fmt"
)

// Known CR/CC parameter codes that are recognized by X.224 but not permitted
// in the Class 0 / ITOT TP0 service whitelist (selectors + 0xC0 + 0xF0 only).
func isKnownClass0ForbiddenParam(code uint8) bool {
	switch code {
	case 0xC3, // version number
		0xC4, // protection / security
		0xC5, // checksum
		0xC6, // additional option selection
		0xC7, // alternative protocol class
		0xC8, // acknowledge time
		0xC9, // throughput
		0xCA, // residual error rate
		0xCB, // priority
		0xCC, // transit delay
		0xCD, // reassignment time
		0xCE: // inactivity timer
		return true
	default:
		return false
	}
}

func validateClass0CRFixed(cdt, classOption uint8) error {
	if cdt != 0 {
		return fmt.Errorf("class 0 CR CDT %d: %w", cdt, ErrHandshake)
	}
	if classOption != 0 {
		return fmt.Errorf("class 0 CR ClassOption 0x%02x: %w", classOption, ErrHandshake)
	}
	return nil
}

func validateClass0CCFixed(cdt, classOption uint8) error {
	if cdt != 0 {
		return fmt.Errorf("class 0 CC CDT %d: %w", cdt, ErrHandshake)
	}
	if classOption != 0 {
		return fmt.Errorf("class 0 CC ClassOption 0x%02x: %w", classOption, ErrHandshake)
	}
	return nil
}

func validateCRReferences(dst, src uint16) error {
	if dst != 0 {
		return fmt.Errorf("CR DST-REF %d want 0: %w", dst, ErrHandshake)
	}
	if src == 0 {
		return fmt.Errorf("CR SRC-REF is zero: %w", ErrHandshake)
	}
	return nil
}

func validateCCReferences(ccDST, ccSRC, localSRC uint16) error {
	if ccDST != localSRC {
		return fmt.Errorf("CC DST-REF %d != local SRC-REF %d: %w", ccDST, localSRC, ErrHandshake)
	}
	if ccSRC == 0 {
		return fmt.Errorf("CC SRC-REF is zero: %w", ErrHandshake)
	}
	return nil
}

// validateMinimalClass0DT checks Class 0 minimal DT header fields.
// typeOctet must be 0xF0; tpduNRAndEOT high bit is EOT, low 7 bits TPDU-NR.
func validateMinimalClass0DT(li int, typeOctet, tpduNRAndEOT uint8) error {
	if li != 2 {
		return fmt.Errorf("class 0 DT LI %d want 2: %w", li, ErrHandshake)
	}
	if typeOctet != 0xF0 {
		return fmt.Errorf("class 0 DT type 0x%02x want 0xF0: %w", typeOctet, ErrHandshake)
	}
	if tpduNRAndEOT&0x7F != 0 {
		return fmt.Errorf("class 0 DT TPDU-NR %d want 0: %w", tpduNRAndEOT&0x7F, ErrHandshake)
	}
	return nil
}

func validateCRParameters(params []Parameter) error {
	for _, p := range params {
		if isKnownClass0ForbiddenParam(p.Code) {
			return fmt.Errorf("CR forbidden parameter 0x%02x: %w", p.Code, ErrHandshake)
		}
		// Unknown parameters are ignored for service semantics.
	}
	return nil
}

func validateCCParameters(params []Parameter) error {
	for _, p := range params {
		if isKnownClass0ForbiddenParam(p.Code) {
			return fmt.Errorf("CC forbidden parameter 0x%02x: %w", p.Code, ErrHandshake)
		}
		// Unknown parameters on CC are a protocol error.
		if p.Code != ParamCallingSelector && p.Code != ParamCalledSelector &&
			p.Code != ParamTPDUSize && p.Code != ParamPreferredMaxTPDUSize {
			return fmt.Errorf("CC unknown parameter 0x%02x: %w", p.Code, ErrHandshake)
		}
	}
	return nil
}

// validateServerCalledSelector implements default Accept LocalSelector policy.
// localSelector nil → no requirement; non-nil → CR called must be present and equal.
func validateServerCalledSelector(localSelector, crCalled []byte) error {
	if localSelector == nil {
		return nil
	}
	if crCalled == nil {
		return fmt.Errorf("called selector absent: %w", ErrHandshake)
	}
	if !bytes.Equal(localSelector, crCalled) {
		return fmt.Errorf("called selector mismatch: %w", ErrHandshake)
	}
	return nil
}

// validateClientCCSelector implements client CC selector echo validation.
// remoteConfigured nil → no equality requirement; retain any returned selector.
// When remoteConfigured is present and CC returns a selector, they must match.
// CC omission is allowed.
func validateClientCCSelector(remoteConfigured, ccResponding []byte) error {
	if remoteConfigured == nil {
		return nil
	}
	if ccResponding == nil {
		return nil
	}
	if !bytes.Equal(remoteConfigured, ccResponding) {
		return fmt.Errorf("CC selector mismatch: %w", ErrHandshake)
	}
	return nil
}

func validateConnectDataLength(data []byte) error {
	if len(data) > MaxConnectDataLength {
		return fmt.Errorf("connect data length %d > %d: %w", len(data), MaxConnectDataLength, ErrInvalidConfig)
	}
	return nil
}

func validateSelectorLength(sel []byte, what string) error {
	if len(sel) > MaxParameterValueLength {
		return fmt.Errorf("%s length %d: %w", what, len(sel), ErrInvalidConfig)
	}
	return nil
}

func validateMaxTSDULength(n int) error {
	if n < 0 {
		return fmt.Errorf("MaxTSDULength %d: %w", n, ErrInvalidConfig)
	}
	return nil
}

func validateSizeProfile(p SizeProfile) error {
	if p != SizeProfileRFC1006Compat && p != SizeProfilePreferredMaximum {
		return fmt.Errorf("SizeProfile %d: %w", p, ErrInvalidConfig)
	}
	return nil
}

func validateConnectAction(a ConnectAction) error {
	if a != ConnectReject && a != ConnectAccept {
		return fmt.Errorf("ConnectAction %d: %w", a, ErrInvalidConfig)
	}
	return nil
}

// validateWriteTSDULength rejects empty or oversize TSDUs before protocol I/O.
func validateWriteTSDULength(tsduLen, maxTSDU int) error {
	if maxTSDU == 0 {
		maxTSDU = DefaultMaxTSDULength
	}
	if tsduLen == 0 {
		return fmt.Errorf("%w", ErrEmptyTSDU)
	}
	if tsduLen > maxTSDU {
		return fmt.Errorf("TSDU length %d > %d: %w", tsduLen, maxTSDU, ErrTSDUTooLarge)
	}
	return nil
}

// validateReassemblyBound reports whether reassembled length exceeds MaxTSDULength.
// Returns ErrTSDUTooLarge when exceeded (engine must abort the connection).
func validateReassemblyBound(reassembledLen, maxTSDU int) error {
	if maxTSDU == 0 {
		maxTSDU = DefaultMaxTSDULength
	}
	if reassembledLen > maxTSDU {
		return fmt.Errorf("reassembly length %d > %d: %w", reassembledLen, maxTSDU, ErrTSDUTooLarge)
	}
	return nil
}
