// SPDX-License-Identifier: MIT

// Package cotp implements X.224 / COTP (Connection-Oriented Transport Protocol)
// TPDU parsing and encoding for use over RFC 1006 / RFC 2126 TPKT framing.
//
// This package is a TPDU codec. It does not implement X.214 transport-service
// primitives or X.224 connection state machines. See docs/COMPLIANCE.md.
//
// Input to decode is one complete COTP TPDU payload, typically already
// extracted from one TPKT packet by github.com/otfabric/go-tpkt v1 (e.g. the slice
// returned by tpkt.DecodePacket or tpkt.Reader.ReadPacket). The package does not
// handle TPKT framing; that is the responsibility of go-tpkt. Do not pass an
// entire TPKT packet to Decode.
//
// API philosophy:
//   - Strict on malformed structure: reject invalid wire data; no silent normalization.
//   - Explicit over magical: behavior is documented; no hidden defaults beyond documented canonical marshal.
//   - Preserve wire information where possible: unknown parameters and structural variants are kept for replay and debugging.
//   - No hidden normalization beyond documented canonical marshal behavior.
//   - Correctness first, convenience second: safe for protocol tooling and production use.
//
// Codec policies (documented intentional behavior):
//   - LI must cover the TPDU fixed part (X.224 13.2.2.1); undersized LI returns ErrInvalidLI.
//   - CR/CC user data after the header is exposed and round-tripped; CR total length ≤ 128 octets.
//   - Duplicate known CR/CC parameters (0xC1/0xC2/0xC0) follow X.224 13.2.3: last value wins.
//   - Canonical CR/CC encode order (0xC1, 0xC2, 0xC0) is a local deterministic choice, not an X.224 mandate.
//   - LooksLike* helpers are classification-only and use the same type masks as PeekType/Decode.
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
