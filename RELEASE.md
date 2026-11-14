# go-cotp Releases

## v1.4.0

**Date:** 2026-11-14
**Previous release:** v1.3.1

No exported identifier is added, removed or changed. The entries under "Breaking" change, in the cases they name, which input the encoders and five decoders accept and which error a write timeout over TLS returns. Nothing else changes for a caller.

### Breaking

- **A write timeout over TLS ends the connection.** Over a `*tls.Conn` passed to `Connect` or `Accept`, a `WriteTSDU` that its context ends (a deadline, or a cancellation) after it wrote to the stream aborts the connection: the error matches `ErrClosed` and the context error, also when no octet of the TSDU was accepted, every later call and `Close` return it, and the stream is closed. Before, such a write returned the bare context error and left the `Conn` open, and the next write failed with the stream's own error. crypto/tls fails every write after one that timed out, so that `Conn` could not write again: there is nothing to restore, and a caller that wants to go on opens a new connection. Unchanged: reads over TLS, a context that ends before the write starts (while it waits its turn), and every other stream, where a write that moved no octet still leaves the connection open. go-cotp recognises the `*tls.Conn` type itself; a stream that wraps one in another type is treated like TCP. The rule for both is in the doc comment of `WriteTSDU` and in ERRORS.md.
- **The encoders refuse a CDT above 15 and a TPDU-NR above 127.** `(*CR)`, `(*CC)`, `(*AK)` and `(*RJ).MarshalBinary` return `ErrMissingRequiredField` for a CDT that does not fit its 4 bits, `(*DT)` and `(*ED).MarshalBinary` for a TPDU-NR that does not fit its 7 bits (X.224 §13.3.3, §13.4.3, §13.7.3, §13.8.3, §13.9.3, §13.11.3). Before, they wrote the low bits without an error. A caller that wants those octets masks the value itself before it encodes (`cdt & 0x0F`, `nr & 0x7F`), which writes what the encoder wrote before.
- **`(*DT).MarshalBinary` writes only what `DecodeDT` reads back as it was built.** It returns `ErrUnsupportedDTVariant` for `Parameters` without a `DestinationRef` (X.224 §13.7.1 a) gives the class 0 and 1 format no variable part) and for a variable part of odd length, which makes LI odd, the extended format (§13.7.4 NOTE). Before, it wrote both, and `DecodeDT` refused them or read them as a different DT. No option restores that output. A normal-format DT with a variable part of even length, and a class 0 and 1 DT without parameters, encode as before; the TP0 service writes only the latter and is not affected.
- **DC, ER, AK, EA and RJ with octets after their header are refused.** These TPDUs have no data field: their structures end with the header (X.224 §13.6.1, §13.9.1, §13.10.1, §13.11.1, §13.12.1), and a TPDU that does not comply with its structure is invalid (§3.2.16). `DecodeDC`, `DecodeER`, `DecodeAK`, `DecodeEA`, `DecodeRJ`, `Decode` and `DecodeWithRaw` return `ErrLengthMismatch` for them. Before, they decoded the header and dropped the octets after it. A tool that reads such TPDUs, from a capture for example, and wants the old result passes `b[:1+int(b[0])]`, the header that LI announces, once it has checked that `b` is that long. The TP0 service refused or aborted on these TPDUs before and still does; one with octets after its header is now reported as a malformed TPDU (`ErrHandshake`) instead of an unexpected one (`ErrUnexpectedTPDU`, `*UnexpectedTPDUError`).

### Dependencies

- Built on go-tpkt v1.2.0 (was v1.1.0). In go-tpkt v1.2.0 a `Reader` or `Writer` that failed inside a packet stays failed and returns `tpkt.ErrStreamMisaligned` on every later call. go-cotp already ended the connection at the first failure inside a packet, so later calls return that terminal error and `tpkt.ErrStreamMisaligned` does not reach a caller (ERRORS.md). Should a reader or writer in that state ever reach an open connection, the call ends it with `ErrClosed` and is not taken for the end of the caller's context. A module that also imports go-tpkt directly gets v1.2.0 with this release; go-tpkt's RELEASE.md lists its changes.

### Documentation

- The places that v1.3.1 recorded "as it is" now describe the new behaviour: `doc.go`, the doc comments of the encoders, of `DecodeDC`, `DecodeER`, `DecodeAK`, `DecodeEA`, `DecodeRJ` and of `ErrLengthMismatch`, `ErrUnsupportedDTVariant` and `ErrMissingRequiredField`, API.md, ERRORS.md, LIMITATIONS.md, README.md, ARCHITECTURE.md, docs/COMPLIANCE.md (C-CR to C-ER; C-DC and C-RJ are now "pass"), the design table in docs/TP0_API_DESIGN.md and TESTING.md (row L6). `docs/api/go-cotp.md` is regenerated.
- ERRORS.md has a table of what a write timeout does over a `*tls.Conn` and over any other stream, and says how go-tpkt's failed state is handled.

### Tests

- `TestTSDU_WriteTimeoutOverTLSEndsConnection`: `Connect` and `Accept` over TLS 1.3 on `net.Pipe` in a synctest bubble, the peer not reading; a deadline and a cancellation each end the connection with `ErrClosed` and the context error, with no octet counted, and the next calls, `Close` and the peer see the end. `TestTSDU_IdleReadTimeoutOverTLSKeepsOpen`: an idle read timeout over TLS leaves the connection usable in both directions.
- `TestMarshal_CDTAndTPDUNRBounds`: CDT 0, 1, 14, 15 and TPDU-NR 0, 1, 126, 127 encode and decode back unchanged; 16, 17, 128, 255 and 128, 129, 255 are refused, for every encoder that writes them.
- `TestMarshalDT_OnlyFormatsDecodeDTReadsBack`: a class 0 and 1 DT with parameters is refused; a normal-format variable part of 0 to 7 and 248 to 251 octets encodes when LI is even and at most 254, and decodes back.
- `TestDecode_NoOctetsAfterTheHeaderOfTPDUsWithoutDataField`: each of DC, ER, AK, EA and RJ, with and without a variable part, followed by 1, 2 and 64 octets, through the typed decoder, `Decode` and `DecodeWithRaw`. `TestOpenState_NoDataFieldTPDUWithOctetsAfterHeader`: the same TPDUs in the open state.
- `TestTSDU_MidPacketFailureThenNextCall`: a deadline and an end of the stream inside a TPKT packet on read, a deadline inside a packet on write; the call after it returns the same terminal error. `TestClassify_MisalignedStreamEndsConnection`: a TPKT reader or writer already in go-tpkt's failed state ends the connection with `ErrClosed`, under every kind of context.
- The fuzz invariants follow the new rules: `FuzzMarshalParameters` requires every TPDU an encoder writes to decode to the same parameters, and refuses a DT variable part of odd length; the decoder targets require a DC, ER, AK, EA or RJ to end with its header and re-encode to every octet that was read, with a seed that has two octets after the header.

---

## v1.3.1

**Date:** 2026-11-14
**Previous release:** v1.3.0

No exported identifier is added, removed or changed. The entries under "Changed" alter which error a call returns, or which input a decoder accepts, in the cases they name.

### Changed

- **Memory of a read.** `ReadTSDU` reassembles a TSDU in one buffer whose capacity never exceeds `MaxTSDULength`, whatever the size and number of the segments. One call holds less than twice `MaxTSDULength`, plus one TPKT packet, and a partly received TSDU is held until the context of that call ends. The doc comment of `ReadTSDU`, LIMITATIONS.md and the limits table in SECURITY.md state the bound. The returned slice is the caller's, as before; it has no capacity beyond its length.
- **`DecodeDT` follows the LI rule of X.224 §13.7.4 NOTE:** an even LI is the normal class 2 to 4 format, an odd LI the extended one, which this codec does not decode. A DT with an odd LI of 5 or more is rejected with `ErrUnsupportedDTVariant` by `DecodeDT`, `Decode`, `DecodeWithRaw` and `ExtractUserData`, as README.md, API.md, ERRORS.md and LIMITATIONS.md describe for the extended format. LI 2 and an even LI of 4 or more decode as before. The TP0 service accepts only LI 2 and is not affected. The encoder is unchanged: `(*DT).MarshalBinary` does not refuse a variable part of odd length, and `DecodeDT` rejects the DT it then builds (API.md, "Encode").
- **A connection timeout reported by the operating system is a disconnect.** When a read or a write fails with `ETIMEDOUT` (keep-alive or retransmission without an answer), `ReadTSDU`, `WriteTSDU`, `Connect` and `Accept` return an error that matches `ErrDisconnected`, a `*DisconnectError` carrying the cause. Before, that failure matched `ErrClosed` and `context.DeadlineExceeded` when the context had a deadline, although the deadline had not passed, and matched no sentinel when it had none. Only a deadline that go-cotp armed on the stream for the caller's context is reported as that context ending, which is what ERRORS.md reserves `ErrClosed` with a context error for.
- **Decoded slices are clipped.** Selectors, parameter values and user data returned by the decoders alias the input, as documented, and now have no capacity beyond their own octets: an `append` to one of them allocates instead of writing into the input buffer or into another decoded field.
- **The zero `Conn`.** `ReadTSDU` and `WriteTSDU` on a `Conn` that does not come from `Connect` or `Accept` return `ErrClosed` at once. Before, they waited for their context to end.

### Documentation

- SECURITY.md has a table of resource limits: the limit, its default, where it is enforced and the test that pins it. It also says what go-cotp leaves to the caller: the number of connections, and handshake and idle time, which only the caller's context bounds. The server example in README.md gives `Accept` a context with a deadline.
- Corrected statements. The TPDU size codes 0x0C to 0x10 are accepted in class 0 since v1.0.1; docs/COMPLIANCE.md (B-13) and docs/TP0_API_DESIGN.md (§5.3 and the examples derived from it) said they were refused, and now record the deviation from X.224 §13.3.4 b). The service validates the class and option octet (B-11). Class 0 has a state machine and segmentation (COMPLIANCE.md, section D). `ErrUnknownTPDUType` is not returned (ERRORS.md). LIMITATIONS.md no longer names old go-cotp versions for its consumers.
- Recorded as it is, with no change in behaviour: the encoders write CDT as its low 4 bits and TPDU-NR as its low 7 bits; `(*DT).MarshalBinary` writes parameters also without a `DestinationRef`; the decoders ignore octets after the header of a DC, ER, AK, EA or RJ; over TLS a `WriteTSDU` that timed out can leave the `Conn` open while the next write fails (LIMITATIONS.md).
- Doc comments: `Close` (safe to call more than once and from multiple goroutines; returns `ErrClosed` or the first terminal cause, never nil), `ServerConfig.OnConnect` (runs on the goroutine that called `Accept`, between the CR and the CC, and stalls only its own handshake), `Conn` (its zero value), `ReadTSDU` (memory, and ownership of the result).

### Tests

- An allocation budget for `MaxTSDULength` (`TestReadTSDU_PendingReassemblyBudget`): segments of one octet up to one octet below the limit, then the memory the call holds and the memory it allocated, for the default limit and for 64 KiB.
- The decoder fuzz targets assert invariants: a documented sentinel on failure; on success clipped sub-slices of the input, a round trip through the encoder that is deeply equal, and, for the types with one encoding, the octets that were read. A table walks every prefix of the golden fixtures.
- The lifecycle contract matrix, listed row by row in TESTING.md: concurrent `Close`, `Close` during a write, a handshake whose context ends, a slow `OnConnect`, every failing path of `Connect`.
- Tests that waited with `time.Sleep` for a call to block synchronise on events: `testing/synctest` over `net.Pipe`, or a stream that reports when its reader waits.
- The test package compiles for 32-bit platforms, and the nightly workflow runs the suite with `GOARCH=386`.
- The TSDU benchmarks keep their peer goroutine out of the timed loop and state their scope.

### CI

- The release workflow builds, vets and tests go-mms, go-iec61850 and go-s7comm against the candidate before it creates the tag (`consumers`).

---

## v1.3.0

**Date:** 2026-11-04
**Previous release:** v1.2.0

### Added

- `ServerConfig.EchoSelectors`: the CC returns the CR's calling selector (0xC1) and, as the responding selector (0xC2), `LocalSelector` or else the CR's called selector, as libiec61850 and iec61850-rust servers do (X.224 §13.3.4: a selector given in the request "may be returned in the confirmation"). A selector absent from the CR stays absent. Off by default; go-mms turns it on for MMS servers.

### Changed

- A client no longer fails the handshake when the CC's 0xC2 differs from `ClientConfig.RemoteSelector`. In a CC that parameter is the *responding* transport selector (X.224 §13.3.4), which need not equal the called one; it is kept as `Negotiated().RemoteSelector`. IEDs that answer a called `0001` with `00000001` connected with other stacks but were refused by go-cotp once a remote selector was configured.

### Tests

- CC selectors for every CR selector shape (absent, empty, 1, 2 and 4 octets) with and without `EchoSelectors`; a client keeping a differing responding selector; a strict server (configured `LocalSelector`) refusing an absent, mismatched or 4-octet-vs-2-octet called selector with DR reason 3 (address unknown), the failure reported in otfabric/go-iec61850#28.

---

## v1.2.0

**Date:** 2026-11-03
**Previous release:** v1.1.1

### Changed

- **Go 1.26 is now the minimum** (`go 1.26` in `go.mod`, was 1.23). CI tests Go 1.26 and 1.27. Built on go-tpkt v1.1.0, which has the same minimum.
- **Error classification:** a TPKT framing violation by the peer (invalid version or packet length) now matches `ErrHandshake`, during the handshake (`Connect`, `Accept`) and in the open state (`ReadTSDU`), and still matches the go-tpkt sentinel. Before, it came back as a bare go-tpkt error at a TSDU boundary and in the handshake, and mid-TSDU as `ErrIncompleteTSDU` joined with `ErrDisconnected`. Mid-TSDU it now matches `ErrIncompleteTSDU` and `ErrHandshake`, not `ErrDisconnected`: the stream did not go away, the peer broke the framing.
- All encoders write parameters through one helper whose length check gosec can see (G115); `encodePreferredMaxUnits` and the preferred-size selection no longer narrow integers without a visible bound. Behaviour and error text are unchanged.
- `go fix ./...` applied (`min`, `range` over integers, `new(expr)`, `sync.WaitGroup.Go`).

### Tests

- Encoder length bounds for every TPDU type and the CR/CC selectors, preferred-maximum encoding at each octet boundary, size selection with very large inputs.
- New fuzz targets `FuzzMarshalParameters` and `FuzzEncodePreferredMaxUnits`.
- `TestChaos_CorruptedOpenStream`: a peer that flips, truncates or extends DT TPDUs, or writes octets outside TPKT, after the handshake; every TSDU before the first corruption arrives intact, the reader ends with a classified error and the connection stays failed. Seeds follow `COTP_CHAOS_SEEDS` like the other chaos tests.
- Framing classification tests for the handshake and the open state.

---

## v1.1.1

**Date:** 2026-10-31
**Previous release:** v1.1.0

### Changed

- Policy 1.2: build output in `bin/` and `release/`, a per-package coverage floor, and more tests and CI. No change in behaviour.
- Built on go-tpkt v1.0.2.

---

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
