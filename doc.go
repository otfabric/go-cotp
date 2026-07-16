// SPDX-License-Identifier: MIT

// Package cotp implements a TP0 (Class 0) COTP transport service over RFC 1006
// TPKT, plus a full X.224 TPDU codec.
//
// Service API (preferred for applications):
//
//	Connect / Accept → *Conn → ReadTSDU / WriteTSDU / Close
//
// Connect and Accept take ownership of the net.Conn immediately, perform the
// Class 0 CR/CC handshake using go-tpkt internally, and return an open *Conn.
// Consumers of *Conn must not use go-tpkt. One reader and one writer may run
// concurrently; Close unblocks outstanding operations; a context that expires
// after I/O has started aborts the connection.
//
// Codec API (tools / low-level): Decode / MarshalBinary on individual TPDU
// payloads (no TPKT header). See docs/COMPLIANCE.md and docs/TP0_API_DESIGN.md.
//
// Do not pass an entire TPKT packet to Decode.
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
//   - Duplicate known CR/CC parameters (0xC1/0xC2/0xC0/0xF0) follow X.224 13.2.3: last value wins.
//   - Canonical CR/CC encode order (0xC1, 0xC2, 0xC0, 0xF0) is a local deterministic choice, not an X.224 mandate.
//   - Preferred maximum (0xF0) is typed as wire units; generic codec has no ITOT 511-unit clamp.
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
