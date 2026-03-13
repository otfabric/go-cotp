// Package cotp implements X.224 / COTP (Connection-Oriented Transport Protocol)
// TPDU parsing and encoding for use over RFC 1006 (TPKT).
//
// Input to decode is one complete COTP TPDU payload, typically already
// extracted from one TPKT frame by github.com/otfabric/go-tpkt (e.g. the slice
// returned by tpkt.Decode or tpkt.Reader.ReadFrame). The package does not
// handle TPKT framing; that is the responsibility of go-tpkt.
//
// API philosophy:
//   - Strict on malformed structure: reject invalid wire data; no silent normalization.
//   - Explicit over magical: behavior is documented; no hidden defaults beyond documented canonical marshal.
//   - Preserve wire information where possible: unknown parameters and structural variants are kept for replay and debugging.
//   - No hidden normalization beyond documented canonical marshal behavior.
//   - Correctness first, convenience second: safe for protocol tooling and production use.
//
// Slice aliasing: Returned []byte fields (e.g. Parameter.Value, selector slices)
// may alias the input buffer. Callers must copy if they need to retain or mutate
// data beyond the lifetime of the input slice. This aliasing behavior is part of
// the package contract and must not change silently across minor releases.
//
// Replay/debug: DecodeWithRaw(b) returns Decoded with Raw set to the exact input slice b (may alias).
// Decode does not set Raw. On decode error, no partial value is returned, so Raw is unavailable.
//
// Multi-octet fixed fields (e.g. refs) are decoded and encoded in network byte order (big-endian).
package cotp
