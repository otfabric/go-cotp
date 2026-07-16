// SPDX-License-Identifier: MIT

package cotp

// DecodeWithRaw is like Decode but on success sets Decoded.Raw to the exact input slice b.
// Raw may alias b; callers must copy if retaining or mutating beyond the lifetime of b.
// On error, returns zero Decoded (Raw is unavailable by design).
func DecodeWithRaw(b []byte) (Decoded, error) {
	d, err := Decode(b)
	if err != nil {
		return Decoded{}, err
	}
	d.Raw = b
	return d, nil
}
