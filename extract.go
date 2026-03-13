package cotp

import "fmt"

// ExtractUserData returns the user data payload of a DT or ED TPDU from b.
// The buffer must be a complete COTP TPDU; PeekType must be TypeDT or TypeED.
// For passive decoding or handoff, use Decode then branch on Type; DT.UserData and ED.UserData
// are the payloads for the next protocol (e.g. S7comm, MMS).
// The returned slice may alias b; callers must copy if retaining beyond the lifetime of b.
func ExtractUserData(b []byte) ([]byte, error) {
	t, err := PeekType(b)
	if err != nil {
		return nil, fmt.Errorf("extract user data: %w", err)
	}
	switch t {
	case TypeDT:
		dt, err := DecodeDT(b)
		if err != nil {
			return nil, fmt.Errorf("extract user data: %w", err)
		}
		return dt.UserData, nil
	case TypeED:
		ed, err := DecodeED(b)
		if err != nil {
			return nil, fmt.Errorf("extract user data: %w", err)
		}
		return ed.UserData, nil
	default:
		return nil, fmt.Errorf("extract user data: not DT or ED (type %s): %w", t, ErrInvalidTPDUCode)
	}
}
