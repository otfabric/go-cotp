# go-cotp Releases

## v1.1.0

**Date:** 2026-10-28
**Previous release:** v1.0.4

## Summary

Full-duplex fix: reads and writes now use independent deadlines, so a `*Conn`
can be read by one goroutine while others write — as MMS does — without one
direction's context cutting, extending, or clearing the other's. Consumers
that wrapped the stream to split deadlines themselves (go-mms
`transport/iso` `splitDeadlineConn`) can drop that shim. No API additions;
minor bump because timeout and error classification changed (see below).

## Changes

### Behaviour

- **Per-direction deadlines.** `ReadTSDU` applies its context with
  `SetReadDeadline` only and `WriteTSDU` with `SetWriteDeadline` only; each
  restores its own direction to no deadline when it returns. Previously both
  armed `SetDeadline` (both directions) and cleared it afterwards, so a write
  with a short context could time out a concurrent read, and a finishing
  read cleared a stalled write's deadline (and vice versa). Only the
  `Connect`/`Accept` handshake still uses `SetDeadline`.
- **Cancellation is race-free and honoured with a deadline too.** A context
  cancelled right as an operation returned could leave a past deadline on the
  stream and break every later operation; the cancellation callback is now
  ordered against the operation's end. A context that has a deadline and is
  cancelled early now interrupts the operation too (before, only contexts
  without a deadline were watched).
- **Context expiry before any octet moved is not fatal.** If a context ends
  `ReadTSDU`/`WriteTSDU` before a single octet of the TSDU crossed the stream
  (an idle read, a stalled first write), the call returns the bare
  `ctx.Err()` and the connection stays open; the other direction is
  untouched. Once octets have moved, the connection is still aborted with
  `ErrClosed` + the context error, as before.
- **Serialized callers honour their context while queued.** Concurrent
  `WriteTSDU` calls are serialized for a whole TSDU (segments of different
  TSDUs never interleave), as are concurrent `ReadTSDU` calls; a caller
  waiting for its turn now returns `ctx.Err()` when its context ends, without
  aborting the connection.
- **Reset / broken pipe classify as `ErrDisconnected`.** A TCP reset, broken
  pipe, stream closed underneath go-cotp, or EOF inside a packet now aborts
  with a `*DisconnectError` carrying the cause (joined with
  `ErrIncompleteTSDU` mid-TSDU), as `docs/TP0_API_DESIGN.md` specified.
  Previously these returned the raw network error.

### Tests

- Full-duplex regressions (`duplex_test.go`): a reader survives a concurrent
  write whose context expires, and the reverse; a completing write keeps the
  reader's deadline, and the reverse; cancelled-right-after-return writes
  never poison the stream; queued callers honour their context.
- 16 parallel senders per side alongside one reader per side over `net.Pipe`
  and TCP with multi-segment TSDUs, verified by per-TSDU CRC and per-sender
  order (`-race`).
- Chaos stream: short writes, short reads, jitter, and random resets.
- `FuzzSegmentedRoundTrip`: fuzz-chosen TSDUs over fuzz-chosen stream
  chunking.
- Deadline controller unit tests, including a cancel/disarm race.

### Documentation

- README, API.md, doc.go, docs/TP0_API_DESIGN.md §7, docs/ARCHITECTURE.md:
  concurrency and deadline rules updated.
- ERRORS.md: typed error structs and `ConnectionPhase` constants corrected to
  match the code; idle-timeout and disconnect classification documented.
- Coverage gate raised to 90% (`make coverage-check`, CONTRIBUTING.md).

### Dependencies

- go-tpkt stays at v1.0.1: it is stateless and sets no deadlines.

---

## v1.0.4

**Date:** 2026-07-30
**Previous release:** v1.0.3

## Summary

Patch release: bump go-tpkt to v1.0.1. No API or behaviour changes.

## Changes

### Dependencies

- **go-tpkt** — `v1.0.0` → **v1.0.1** (docs/tooling/coverage; no TPKT API change).

### Unchanged

- No API, wire, or behavioural changes. Import path remains `github.com/otfabric/go-cotp`.

---

## v1.0.3

**Date:** 2026-07-30
**Previous release:** v1.0.2

## Summary

Patch release: move the public API reference to the repository root for consistency with the other otfabric libraries. No API or behaviour changes.

## Changes

### Documentation

- **API.md** — Moved from `docs/API.md` to the repository root; relative links to `docs/ARCHITECTURE.md`, `docs/COMPLIANCE.md`, and `docs/TP0_API_DESIGN.md` updated.
- **docs/API.md** — Short redirect stub pointing at `../API.md` for any bookmarks that still use the old path.
- **README.md**, **CONTRIBUTING.md**, **docs/COMPLIANCE.md**, **docs/TP0_API_DESIGN.md** — Links updated to the root `API.md`.
- **README** — New **Project structure** section (flat root package, `docs/`, `spec/`, `testdata/`, key docs).

### Unchanged

- No API, wire, or behavioural changes. Import path remains `github.com/otfabric/go-cotp`.

---

## v1.0.2

Documentation and lint hygiene. No API changes, no behavior changes.

### Documentation

- Added `ERRORS.md` — error taxonomy covering all sentinel values, the three typed error structs
  (`RejectionError`, `UnexpectedTPDUError`, `DisconnectError`), `ConnectionPhase` constants, and
  `errors.Is` / `errors.As` usage patterns for both the service API and the codec.
- Added link to `ERRORS.md` in `README.md` Documentation section.

### Linting

- Removed a stale `formatters.exclusions.paths: examples` entry from `.golangci.yml`; the
  repository has no `examples/` directory so the exclusion was dead code.

No API changes. No breaking changes.

Import path remains `github.com/otfabric/go-cotp`.

---

## v1.0.1

Improved RFC 1006 Class 0 TPDU size negotiation interoperability with existing industrial protocol stacks while preserving protocol validation for undefined TPDU size codes.

### Interoperability

* Expanded the accepted standard Class 0 TPDU size codes to include 0x0C–0x10 (4096–65536 bytes).
    * This aligns with common RFC 1006 implementations used by industrial protocols such as IEC 61850 MMS.
    * Improves interoperability with widely deployed stacks including libIEC61850 and iec61850bean.
    * Undefined TPDU size codes continue to be rejected during connection establishment.
* Improved negotiation when the client omits the TPDU Size parameter.
    * Connection Confirm (CC) responses advertising a larger standard TPDU size are now capped to the local proposal instead of being rejected.
    * This accommodates implementations that negotiate larger RFC 1006 TPDU sizes (for example 0x10 = 65536) while the local endpoint uses the protocol maximum of 65531 bytes.

### Validation

* Tightened handshake validation tests to distinguish between:
    * valid extended standard TPDU size codes (0x0C–0x10), and
    * undefined TPDU size codes (for example 0x11), which continue to fail the handshake with ErrHandshake.

### Tests

* Updated TPDU size negotiation tests to reflect the extended standard size table.
* Added coverage for negotiation using the newly accepted standard sizes.
* Updated interoperability tests for RFC 1006 compatibility and undefined TPDU size validation.

No API changes. No breaking changes.

Import path remains `github.com/otfabric/go-cotp`.

---

## v0.1.6

go-tpkt v1.0.0 migration, standards compliance audit, codec P0 correctness fixes, and target stack architecture docs.

### Dependencies

- Migrated to `github.com/otfabric/go-tpkt` **v1.0.0** (removed local `replace`).
- Examples and docs use the v1 packet API: `EncodePacket` / `DecodePacket`, `ReadPacket` / `WritePacket`, `ReaderConfig`, error-returning constructors.

### Codec (P0)

- **LI vs fixed part (X.224 13.2.2.1):** decoders reject LI shorter than the TPDU fixed part with `ErrInvalidLI` (`headerBounds`).
- **CR/CC selectors:** encode rejects values longer than 255 octets (`ErrUnexpectedParameterLength`); no silent truncation.
- **LooksLikeDT / DecodeDT:** type mask aligned with `PeekType` (`0xF0`–`0xF1` only).
- **CR/CC user data:** exposed as `UserData`, round-tripped on encode; CR total length capped at 128 octets (`MaxCRTPDULength`, `ErrLengthMismatch`).
- **Duplicate known CR/CC parameters:** follow X.224 13.2.3 last-wins (no longer return `ErrDuplicateKnownParameter`).
- Added focused tests in `p0_test.go`; policies recorded in `doc.go`.

### Tests

- Expanded TPKT↔COTP integration tests (round-trip, multi-packet boundaries, truncation as framing error, nil constructors, invalid reader config).
- Strengthened fuzz invariants (`FuzzDecode` zero-value on error; `FuzzLooksLikeDoesNotPanic`; `FuzzMarshalDecodeRoundTrip`).

### Documentation and specs

- Added [docs/COMPLIANCE.md](docs/COMPLIANCE.md): clause-backed matrix against X.214, X.224 (+ Amd.1), RFC 1006, RFC 2126; gap roadmap (P0 marked done); safe compliance claim.
- Added [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): target OT Fabric service boundaries (TPKT packets → COTP TSDUs → S7/MMS), ownership matrix, dependency rules, and migration sequence.
- Moved public API reference from `API.md` to [docs/API.md](docs/API.md); updated links in README, CONTRIBUTING, COMPLIANCE, and RELEASE.
- README scope/integration sections distinguish codec-today vs engine-target and point at ARCHITECTURE + COMPLIANCE; stack diagram uses TPKT **packet** terminology.
- Reorganized `spec/` (`core/` ITU-T PDFs, `tcp/` RFCs) and expanded [spec/README.md](spec/README.md) with local document links.

Import path remains `github.com/otfabric/go-cotp`.

---

## v0.1.5

Open-source release preparation: MIT license headers, README improvements, and dependency bump. No API or behavior changes.

### Changes

- **License**
  - Added `// SPDX-License-Identifier: MIT` to all first-party Go source files.

- **Documentation**
  - **README.md:** Added table of contents and a dedicated License section.
  - **README.md:** Normalized badge block for public release — added pkg.go.dev badge, reordered badges, and switched Codecov to the tokenless public URL (`codecov.io/gh/...`).

- **Dependencies**
  - Bumped `github.com/otfabric/go-tpkt` from v0.1.2 to v0.1.3.

No breaking changes. Import path remains `github.com/otfabric/go-cotp`.

---

## v0.1.4

**Changed**: Increased minimum required Go version to 1.23 (was 1.21). All documentation, CI, and go.mod references updated accordingly. No code changes.

This release ensures compatibility with Go 1.23. No new features or bugfixes are included.

---

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
  - `docs/API.md` — public API reference (functions, types, errors).
  - `RELEASE.md` — release notes.
  - `CONTRIBUTING.md`, `LICENSE` (MIT), `SECURITY.md`.
  - `Makefile` with `test`, `vet`, `fmt`, `coverage`, `coverage-check` (min 75%), `fuzz`, `bench`, `check`.
  - GitHub Actions workflow (`.github/workflows/test.yml`) for tests, race detector, and coverage on Go 1.21+.

### Dependencies

- **Go:** 1.21 or later.
- **go-tpkt:** `github.com/otfabric/go-tpkt` — used for examples and integration; COTP payloads are typically obtained from `tpkt.DecodePacket` or `tpkt.Reader.ReadPacket`.

### Integration

Designed for the otfabric stack: **TCP → TPKT (go-tpkt) → COTP (go-cotp) → S7comm / MMS / …**. Use go-tpkt for framing; pass the TPKT payload to go-cotp for decode/encode.
