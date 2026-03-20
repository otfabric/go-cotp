# go-cotp Releases

## v0.1.3

**Changed**: Lowered minimum required Go version to 1.21 (was 1.22). All documentation, CI, and go.mod references updated accordingly. No code changes.

This release ensures compatibility with Go 1.21. No new features or bugfixes are included.

---

## v0.1.2

Documentation and API alignment: detection parity, error semantics, and doc fixes.

### Changes

- **Detection helpers**
  - Added `LooksLikeDT`, `LooksLikeDR`, `LooksLikeDC`, `LooksLikeER` so every `Decode*` has a matching `LooksLike*` (full parity with the 10 TPDU types).
  - Tests added for all four in `detect_test.go`.

- **Error semantics**
  - ED `MarshalBinary`: when `DestinationRef` or `TPDUNR` is nil, now returns `ErrMissingRequiredField` instead of `ErrTooShort`. Aligns with documented sentinel and makes classification consistent.
  - New test `TestED_MarshalBinary_MissingRequiredFields` for this path.

- **Documentation**
  - **API.md:** Clarified that all 10 standard TPDU types are supported; `ErrUnsupportedTPDU` is used only for reserved or unknown type codes.
  - **API.md:** Normalized ER struct field alignment in the reference.
  - Detection table in API.md lists all 10 `LooksLike*` helpers in Decode order.

No breaking changes. Import path remains `github.com/otfabric/go-cotp` (package at repo root).

---

## v0.1.0

Initial public release of `github.com/otfabric/go-cotp`, a small, idiomatic Go library that implements X.224 / COTP (Connection-Oriented Transport Protocol) TPDU parsing and encoding for use over RFC 1006 (TPKT).

### Highlights

- **COTP codec**
  - `Decode(b []byte) (Decoded, error)` — parse any supported TPDU into a discriminated struct (`Type` plus one of `CR`, `CC`, `DT`, `DR`, `DC`, `ER`, `ED`, `AK`, `EA`, `RJ`).
  - `DecodeWithRaw(b []byte)` — same as `Decode` but sets `Decoded.Raw` to the input slice for replay/debug.
  - Per-TPDU decoders: `DecodeCR`, `DecodeCC`, `DecodeDT`, `DecodeDR`, `DecodeDC`, `DecodeER`, `DecodeED`, `DecodeAK`, `DecodeEA`, `DecodeRJ`.
  - All 10 TPDU types implement `MarshalBinary()` for encoding; canonical parameter ordering for CR/CC; strict validation (LI, type codes, header length, user-data length for ED).

- **Parameters and wire**
  - Variable-part parameter parsing with unknown parameters preserved in `Parameters []Parameter`.
  - Wire helpers: `ReadLI`, `HeaderLength`, `PeekType`, `ExtractUserData` (DT/ED user data).
  - Detection helpers (classification only): `LooksLikeCR`, `LooksLikeCC`, `LooksLikeED`, `LooksLikeAK`, `LooksLikeEA`, `LooksLikeRJ`, `IsConnectionOriented`, `IsAckType`.

- **Safety and correctness**
  - Sentinel errors (`ErrTooShort`, `ErrInvalidTPDUCode`, `ErrInvalidLI`, `ErrUnsupportedTPDU`, `ErrUnsupportedDTVariant`, `ErrMalformedParameter`, `ErrInvalidEDUserDataLength`, `ErrNilReceiver`, etc.) with `%w` wrapping for `errors.Is` / `errors.As`.
  - Decoded slices may alias the input buffer; documented in package and API.
  - DT v1: minimal (LI=2) and normal (LI≥4) formats; extended format rejected with `ErrUnsupportedDTVariant`.
  - ED user data length enforced (1–16 octets on encode; configurable on decode).

- **Tooling and docs**
  - `doc.go` with package scope, aliasing, and replay behavior.
  - `README.md` with badges, install, usage, integration with go-tpkt, and documentation links.
  - `API.md` — public API reference (functions, types, errors).
  - `RELEASE.md` — release notes.
  - `CONTRIBUTING.md`, `LICENSE` (MIT), `SECURITY.md`.
  - `Makefile` with `test`, `vet`, `fmt`, `coverage`, `coverage-check` (min 75%), `fuzz`, `bench`, `check`.
  - GitHub Actions workflow (`.github/workflows/test.yml`) for tests, race detector, and coverage on Go 1.21+.

### Dependencies

- **Go:** 1.21 or later.
- **go-tpkt:** `github.com/otfabric/go-tpkt` — used for examples and integration; COTP payloads are typically obtained from `tpkt.Decode` or `tpkt.Reader.ReadFrame`.

### Integration

Designed for the otfabric stack: **TCP → TPKT (go-tpkt) → COTP (go-cotp) → S7comm / MMS / …**. Use go-tpkt for framing; pass the TPKT payload to go-cotp for decode/encode.
