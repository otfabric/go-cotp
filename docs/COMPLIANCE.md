# go-cotp Standards Compliance

**Status date:** 2026-07-16  
**Module:** `github.com/otfabric/go-cotp`  
**Framing dependency:** `github.com/otfabric/go-tpkt` v1.0.0  

## Safe compliance claim

**Current (pre-RC, after closure tests):** implements a **TP0-over-TPKT** transport profile (RFC 1006 Class 0) with client/server establishment, TPDU-size negotiation, segmented TSDU transfer, selector handling, and TCP-close release, plus a full X.224 TPDU codec. **Not** a complete X.214 service, **not** all X.224 classes, **not** TP2, and **not** full RFC 2126 / ITOT.

Do not claim: “Full COTP”, “X.224 compliant”, “RFC 2126 compliant”, or “Full ITOT”.

## Specification roles

| Source | Local file | Authority |
| --- | --- | --- |
| ITU-T X.214 (1995) | [`spec/core/T-REC-X.214-199511-I!!PDF-E.pdf`](../spec/core/T-REC-X.214-199511-I!!PDF-E.pdf) | Transport-service definition and TS-user primitives |
| ITU-T X.224 (1995) | [`spec/core/T-REC-X.224-199511-I!!PDF-E.pdf`](../spec/core/T-REC-X.224-199511-I!!PDF-E.pdf) | Canonical COTP TPDU formats, parameters, classes, procedures, state tables |
| X.224 Amendment 1 (1997) | [`spec/core/T-REC-X.224-199708-I!Amd1!PDF-E.pdf`](../spec/core/T-REC-X.224-199708-I!Amd1!PDF-E.pdf) | Relaxes class conformance; expedited-data feature negotiation optional |
| RFC 1006 | [`spec/tcp/rfc1006.txt`](../spec/tcp/rfc1006.txt) | Class 0 over TCP + TPKT |
| RFC 2126 | [`spec/tcp/rfc2126.txt`](../spec/tcp/rfc2126.txt) | ITOT: TP0/TP2 over TCP, updated interoperability |

PDF page numbers below refer to the ITU-T published page footers where practical (e.g. “ITU-T Rec. X.224 (1995 E) p.56”).

## RFC errata snapshot (2026-07-16)

| RFC | Errata note | Impact on this audit |
| --- | --- | --- |
| RFC 1006 | Verified **editorial** erratum exists (check [RFC Editor errata for 1006](https://www.rfc-editor.org/errata_search.php?rfc=1006)) | Does not change TPKT framing ownership (go-tpkt) or codec scope |
| RFC 2126 | Reported **technical** erratum exists (check [RFC Editor errata for 2126](https://www.rfc-editor.org/errata_search.php?rfc=2126)) | Treat as **unclear / human review** until accepted; do not auto-treat as normative |

---

## Matrix schema

| Column | Meaning |
| --- | --- |
| ID | Stable requirement id |
| Requirement | What must hold |
| Source | Document |
| Clause | Clause / section |
| Basis | `RFC normative` / `ITU normative` / `Amendment` / `Derived` / `Security invariant` / `API contract` / `Consumer profile` / `Implementation choice` |
| Current code | Symbol / file |
| Tests | Test coverage |
| Status | `pass` / `partial` / `fail` / `not implemented` / `not applicable` / `unclear` / `documentation gap` / `missing test` |

---

## A. Transport service (X.214)

**Classification of this repository:** **TP0-over-TCP service + TPDU codec** — Class 0 / RFC 1006 profile engine present; not a complete X.214/X.224 implementation.

| ID | Requirement | Source | Clause | Basis | Current code | Tests | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A-01 | T-CONNECT request/indication/response/confirm | X.214 | §12–13 service primitives (p.~table of primitives) | ITU normative | `Connect` / `Accept` | `connect_test.go`, `accept_test.go`, `integration_test.go`, `tcp_test.go`, `adversarial_test.go` | **pass** (TP0) | CR/CC establishment, selectors, connect data, `OnConnect` accept/reject |
| A-02 | T-DATA request/indication | X.214 | Data transfer primitives | ITU normative | `ReadTSDU` / `WriteTSDU` | `tsdu_test.go`, `integration_test.go`, `tcp_test.go` | **pass** (TP0) | Class 0 DT segmentation/reassembly; expedited/TP2 not in scope |
| A-03 | T-EXPEDITED-DATA | X.214 | Expedited data primitives | ITU normative | ED/EA codec | ED tests | partial | Codec only; no service queueing |
| A-04 | T-DISCONNECT | X.214 | Release primitives | ITU normative | DR/DC codec; open-state DR abort; TCP-close | `open_state_test.go`, `integration_test.go` | partial | No graceful DR release API; peer TCP close → `ErrDisconnected`+EOF; open DR aborts (no DC) |
| A-05 | Transport addresses / selectors | X.214 | Addressing | ITU normative | `CallingSelector`/`CalledSelector` raw `[]byte` | CR/CC param tests, `integration_test.go` | partial | Byte selectors enforced in TP0; no semantic TSAP type |
| A-06 | QOS negotiation | X.214 | QOS parameters | ITU normative | — | — | not implemented | Throughput/delay/etc. not modeled |
| A-07 | Error / disconnect indications to TS-user | X.214 | Provider-initiated release | ITU normative | typed errors on `Conn` | engine error tests | partial | Errors returned on ops / `Close`; no separate indication channel |

---

## B. Common COTP protocol (X.224)

| ID | Requirement | Source | Clause | Basis | Current code | Tests | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B-01 | TPDU type-code extraction | X.224 | 13.2.2.2 (p.56) | ITU normative | `PeekType`, `Decode` | wire/detect tests | pass | DT mask `0xFE` for ROA bit |
| B-02 | LI = header length excl. LI and user data; max 254; 255 reserved | X.224 | 13.2.1 (p.56) | ITU normative | `ReadLI`, `MaxLI` | `wire_test.go` | pass | LI=255 → `ErrInvalidLI` |
| B-03 | LI ≥ NSDU size is protocol error | X.224 | 13.2.1 (p.56) | ITU normative | buffer vs `1+LI` checks | short-buffer tests | pass | Enforced as `ErrTooShort` when `len < 1+LI` |
| B-04 | Fixed part must fit within header defined by LI | X.224 | 13.2.2.1 (p.56) | ITU normative | `headerBounds` | `p0_test.go` | pass | Undersized LI → `ErrInvalidLI` |
| B-05 | Variable-part TLV encoding | X.224 | 13.2.3 (p.56–57) | ITU normative | `parseVariablePart`, `parseCRCCVariablePart` | params tests | pass | code+length+value |
| B-06 | Unknown parameter in CR: ignore | X.224 | 13.2.3 (p.57) | ITU normative | preserved in `Parameters` | params tests | partial | Preserved (tooling-friendly) rather than silently dropped; not treated as error |
| B-07 | Unknown parameter in non-CR: protocol error | X.224 | 13.2.3 (p.57) | ITU normative | codec preserves; engine rejects | `open_state_test.go`, CC handshake validators | **pass** (engine) / pass (codec tooling) | Open-state DT and CC reject unknown / Class-0-forbidden parameters; CR still ignores unknown params per X.224 |
| B-08 | Duplicate parameter: last value wins | X.224 | 13.2.3 (p.57) | ITU normative | `parseCRCCVariablePart` | params / p0 tests | pass | Known CR/CC params: last wins; unknown params: all preserved |
| B-09 | Parameter order arbitrary | X.224 | 13.2.3 (p.57) | ITU normative | decode any order; encode CR/CC canonical C1→C2→C0 | encode tests | partial | Canonical order is **local deterministic policy**, not X.224-mandated |
| B-10 | Transport references DST/SRC | X.224 | 13.3–13.6 | ITU normative | fields on CR/CC/DR/DC/…; engine allocate/validate | unit + connect/accept tests | **pass** (TP0) | Non-zero local refs; peer SRC-REF=0 rejected; CC DST-REF checked |
| B-21 | Non-zero connection references + uniqueness | X.224 | 6.5 (shall not be zero / not in use or frozen) | ITU normative | `referenceAllocator` wired into `Connect`/`Accept` | `reference_allocator_test.go`, `connect_test.go`, `accept_test.go` | **pass** (TP0) | Allocator collision-safe; release on every failure/terminal path |
| B-11 | Class and option negotiation | X.224 | 6.5, 13.3.3 | ITU normative | `ClassOption` octet stored | — | not implemented | No negotiation; value not validated (`ErrInvalidClassOption` unused) |
| B-12 | Alternative protocol classes | X.224 | 6.5 / CR variable part | ITU normative | unknown param only | — | not implemented | No typed param |
| B-13 | TPDU size parameter (0xC0) | X.224 | 13.3.4 b) | ITU normative | `TPDUSize *uint8`; engine nego | CR/CC + `size_*_test.go`, `integration_test.go` | **pass** (TP0) | Class 0 codes 0x07–0x0B; 0x0C/0x0D rejected; negotiated size enforced on open DT |
| B-14 | Preferred maximum TPDU size (generic wire) | X.224 | 13.3.4 c), 6.5 | ITU normative | `PreferredMaxTPDUSize *uint32`; `PreferredMaxTPDULength` / `PreferredMaxTPDUUnits` | `preferred_max_codec_test.go` | **pass** | Typed units; exact uint64 helpers; permissive decode / canonical encode; no ITOT 511 clamp; last-wins duplicates |
| B-22 | Preferred maximum ITOT service ceiling | RFC 1006/2126 + design | ITOT max TPDU 65531 | Transport profile / Implementation choice | `size_nego.go` + `Connect`/`Accept` | `size_*_test.go`, `integration_test.go`, `adversarial_test.go` | **pass** (TP0) | units ≤ 511; path-normalized selection; omitted CC under PreferredMaximum rejected |
| B-15 | Calling/Called TSAP selectors | X.224 | 13.3.4 a) | ITU normative | `0xC1`/`0xC2` typed | params / p0 tests | partial | Raw bytes; encode rejects len>255; semantic TSAP type still absent |
| B-16 | Checksum parameter (class 4) | X.224 | 13.2.3.1, 6.17 | ITU normative | — | — | not implemented | |
| B-17 | Additional option selection | X.224 | 13.3.4 / 6.5 | ITU normative | unknown param only | — | not implemented | Includes expedited negotiation |
| B-18 | Ack time, throughput, residual error, priority, transit delay, reassignment, inactivity | X.224 | 13.3.4 | ITU normative | — | — | not implemented | |
| B-19 | User data in CR/CC | X.224 / RFC 1006 | X.224 13.3 / 6.5; RFC 1006 exception | mixed | `CR.UserData` / `CC.UserData` | `p0_test.go` | pass | Codec exposes and round-trips. **ITOT profile** (RFC 1006/2126) permits CR/CC connect data as an exception to standard Class 0; generic X.224 Class 0 does not make connection-establishment user data available when Class 0 is preferred. TP0 service API must word this as profile connect data (see [TP0_API_DESIGN.md](TP0_API_DESIGN.md)) |
| B-20 | Error / reason codes | X.224 | DR reason, ER reject cause | ITU normative | `Reason`, `RejectCause` uint8 | DR/ER tests | partial | Enumerations not validated |

---

## C. TPDU formats

| ID | TPDU | Requirement | Source | Clause | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| C-CR | CR | Fixed part CDT/DST/SRC/ClassOption + var params | X.224 | 13.3 (p.57+) | pass / partial | Typed C1/C2/C0; UserData; CR≤128; many optional CR params still untyped |
| C-CC | CC | Same family as CR | X.224 | 13.4 | pass / partial | Same as CR minus 128-octet cap |
| C-DR | DR | Refs, reason, params, user data | X.224 | 13.5 | partial | User data exposed; ≤64-octet limit not enforced |
| C-DC | DC | Refs + params | X.224 | 13.6 | partial | Trailing octets ignored |
| C-DT | DT | Minimal (class 0/1) and normal; extended optional | X.224 | 13.7 | partial | Minimal LI=2 + normal LI≥4; **extended rejected** (`ErrUnsupportedDTVariant`); ROA bit not modeled on encode (always 0). Class 0 user data per DT = negotiated TPDU size − 3 (§13.7.5); see E-09 vs RFC 1006 65524 |
| C-ED | ED | Normal/extended; user data 1–16 | X.224 | 13.8 | partial | Normal only; 1–16 enforced; RFC 1006/2126 use DT-like ED for TP0 — **profile conflict** (see E/F) |
| C-AK | AK | Normal/extended + CDT | X.224 | 13.9 | partial | Normal only |
| C-EA | EA | Normal/extended | X.224 | 13.10 | partial | Normal only |
| C-RJ | RJ | Fixed; no variable part | X.224 | 13.11 | pass | LI must be exactly 4 (LI&lt;4 → ErrInvalidLI; LI&gt;4 → ErrMalformedParameter) |
| C-ER | ER | DST-REF, reject cause, params | X.224 | 13.12 | partial | Cause values not enum-checked |

---

## D. Class-specific procedures

| Class | Codec coverage | State machine | Segmentation | Flow control | Multiplexing | Expedited | Timers | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | CR/CC/DT(min)/DR/ER (+DC) wire | none | none | n/a | n/a | RFC1006 ED variant unclear vs X.224 | none | **codec only** |
| 1 | same + ED/EA wire possible | none | none | none | none | none | none | **codec only** |
| 2 | DT normal, AK, RJ, ED, EA wire | none | none | none | none | none | none | **codec only** |
| 3 | wire fields overlap class 2/4 | none | none | none | none | none | none | **codec only** |
| 4 | checksum absent | none | none | none | none | none | none | **codec only** |

Annex A state tables (X.224 Annex A): **not implemented**.

---

## E. RFC 1006 TCP profile

| ID | Requirement | Source | Clause | Basis | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| E-01 | TPKT framing | RFC 1006 | §6 | RFC normative | pass (dependency) | Delegated to go-tpkt v1 |
| E-02 | Class 0 over TCP | RFC 1006 | body | RFC normative | **pass** (TP0) | Handshake + segmented TSDU + open-state abort matrix; integration/adversarial/TCP tests green |
| E-03 | One TC ↔ one TCP connection | RFC 1006 | mapping | RFC normative | **pass** (TP0) | `Connect`/`Accept` own one `net.Conn` immediately; covered by `tcp_test.go` |
| E-04 | TCP stream ≠ TPDU boundary | RFC 1006 | TPKT | RFC normative | pass (dependency) | go-tpkt `ReadPacket` |
| E-05 | Port 102 | RFC 1006 | Status / § | RFC normative | not applicable | Profile concern, not codec |
| E-06 | Default max TPDU 65531 | RFC 1006 | TPKT length | RFC normative | **pass** (TP0) | `DefaultMaxTPDULength` / omitted-size path; see [TP0_API_DESIGN.md](TP0_API_DESIGN.md) |
| E-07 | Expedited: modified ED ≈ DT | RFC 1006 | expedited notes | RFC normative | **unclear** / partial | Library ED follows X.224 13.8 shape (DST-REF + NR), not the RFC 1006 “ED looks like DT” experimental form |
| E-08 | TCP close → disconnect | RFC 1006 | mapping | RFC normative | **pass** (TP0) | Peer TCP close → `ErrDisconnected`+EOF; local `Close` unblocks waiters; first terminal cause wins |
| E-09 | Max TSDU 65524 for TPDU 65531 | RFC 1006 | body | RFC normative | **discrepancy** | Conflicts with X.224:1995 §13.7 Class 0 DT (TPDU − 3 → 65528 user octets **per DT segment**). No verified RFC 1006 erratum. **go-cotp TP0 uses X.224 for segmentation**; 65524 retained here only as a documented discrepancy. 65528 is max per-DT payload, not a max TSDU |
| E-10 | Omitted CC size → local-capped negotiated max | RFC 1006 / 2126 / design | — | Implementation choice / installed-base compatibility | partial | Wired through client `Connect` via `interpretCCSize`; see [TP0_API_DESIGN.md](TP0_API_DESIGN.md) §5.6 |

---

## F. RFC 2126 ITOT profile

| ID | Requirement | Source | Clause | Basis | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| F-01 | Class 0 over TCP | RFC 2126 | §4.1 | RFC normative | partial | TP0 engine implements the Class 0 subset; full RFC 2126 claim reserved until RC + interoperability |
| F-02 | Class 2 over TCP | RFC 2126 | §4.2 | RFC normative | not implemented | |
| F-03 | TPKT | RFC 2126 | §4.3 / §6.10 | RFC normative | pass (dependency) | go-tpkt; reserved octet ignored is **go-tpkt** guarantee |
| F-04 | IPv4/IPv6 neutrality | RFC 2126 | addressing | RFC normative | not applicable | Codec has no addressing |
| F-05 | Expedited negotiation / ED path | RFC 2126 | §4.1 / §6.7–6.8 | RFC normative | not implemented | |
| F-06 | Explicit vs non-explicit flow control | RFC 2126 | Class 2 options | RFC normative | not implemented | |
| F-07 | Multiplexing | RFC 2126 | Class 2 | RFC normative | not implemented | |
| F-08 | Forward/reverse connection procedures | RFC 2126 | §6.9 | RFC normative | not implemented | |
| F-09 | TCP close/reset handling | RFC 2126 | mapping | RFC normative | not implemented | |
| F-10 | Technical erratum | RFC 2126 | errata | unclear | unclear | Do not treat reported technical erratum as normative until verified |

---

## G. Security and parser safety

| ID | Requirement | Basis | Status | Notes |
| --- | --- | --- | --- | --- |
| G-01 | Validate lengths before slicing | Security invariant | pass | Variable-part overrun and LI≥fixed-part checked |
| G-02 | LI=255 reserved | ITU normative | pass | |
| G-03 | Parameter length before value | Security invariant | pass | |
| G-04 | Bounded allocations | Security invariant | pass | No grow loops unbounded beyond input |
| G-05 | Nil receiver MarshalBinary | API contract | pass | `ErrNilReceiver` |
| G-06 | No partial Decoded on error | API contract | pass | FuzzDecode asserts zero value |
| G-07 | Aliasing documented | API contract | pass | `doc.go`, `docs/API.md` |
| G-08 | No panic on arbitrary input | Security invariant | pass | Fuzz helpers |
| G-09 | `errors.Is` wrapping | API contract | pass | `%w` used |
| G-10 | Selector encode len>255 | Security invariant | pass | `ErrUnexpectedParameterLength` |
| G-11 | Duplicate known-param policy | ITU normative | pass | Last-wins (X.224 13.2.3); documented in `doc.go` |

---

## API assessment (Phase 3 summary)

### 3.1 `Decoded` tagged union

**Keep for v0; revisit for v1.** Pros: simple, no interface assertion. Cons: easy to construct invalid states (`Type` vs pointers), large struct. Alternatives: sealed interface `type TPDU interface { tpdu(); MarshalBinary() ([]byte, error) }` or decode options. `DecodeWithRaw` is useful for tooling; a `DecodeOption` would be cleaner for v1 but is not required now.

### 3.2 Generic vs per-type decode

Both justified: `Decode` for demux; `Decode*` for engine paths that already know the type. Shared path is PeekType → Decode*. **DT type mask is aligned:** `LooksLikeDT`, `PeekType`, and `DecodeDT` all use `0xFE` (`0xF0`–`0xF1` only).

### 3.3 `MarshalBinary`

Implements `encoding.BinaryMarshaler`. Canonical CR/CC parameter order is a **local deterministic encoding choice**, not an X.224 rule. Unknown params after known typed fields. Typed fields win over duplicate codes in `Parameters`.

### 3.4 `LooksLike*`

Classification-only; **must never be presented as validation**. `LooksLikeDT` uses the same `0xFE` mask as `PeekType`/`DecodeDT` (0xF0–0xF1).

### 3.5 Error model

| Sentinel | Issue |
| --- | --- |
| `ErrLengthMismatch` | **Used** for CR total length > `MaxCRTPDULength` (128) |
| `ErrUnknownTPDUType` | Unused |
| `ErrInvalidClassOption` | Unused |
| `ErrUnsupportedTPDU` | Effectively unreachable via `PeekType` |
| Invalid / reserved / unknown / unsupported | Overlapping concepts; needs v1 cleanup |

---

## Target architecture

Service boundaries, dependency rules, and consumer migration sequence are defined in **[ARCHITECTURE.md](ARCHITECTURE.md)**.

Key invariants for this repository:

- go-cotp owns both the **TPDU codec** and (target) the **transport-service engine**.
- go-cotp is the **only** production-stack consumer of go-tpkt.
- go-s7comm / go-mms consume **complete TSDUs** from an established COTP `Conn`, not raw DT/TPKT.

---

## Gap-ranked roadmap

Aligned with [ARCHITECTURE.md](ARCHITECTURE.md) migration sequence.

### P0 — codec correctness / security — **done** (v0.1.6)

1. ~~Enforce `LI ≥ fixed-part length` (X.224 13.2.2.1).~~
2. ~~Fix CR/CC selector encode length >255 (error, not truncate).~~
3. ~~Align `LooksLikeDT` mask with `PeekType` / `Decode`.~~
4. ~~CR/CC user-data: expose and round-trip; CR total ≤128 (`ErrLengthMismatch`).~~
5. ~~Duplicate known params: X.224 last-wins; documented.~~

### P1 — freeze TP0 service API, then implement TP0 engine — **engine done; closure in progress**

1. **API design (rev. 7.1):** [TP0_API_DESIGN.md](TP0_API_DESIGN.md) — architecture **frozen**; public API **frozen**; negotiation **implementation-frozen** (`0xF0` codec + cases 1–60 green).
2. ~~P1 negotiation prerequisites~~ **done** (typed `0xF0`, pure size-negotiation/handshake validators, reference allocator).
3. ~~Implement TP0 engine~~ **done**:
   - Connection state machine; collision-safe non-zero refs; Class 0 CDT/ClassOption/DT bits and parameter whitelist
   - CR/CC negotiation (dual-offer `0xC0`/`0xF0`, path-normalized ceilings, selectors, ITOT connect data ≤32)
   - Unknown non-CR parameters → protocol error; Class-0-forbidden known params rejected
   - DT segmentation / reassembly → complete TSDUs
   - DR for CR refuse / ER for invalid Class 0 CR; open+DR → abort (no DC); TCP close mapping
   - go-tpkt used only inside go-cotp production paths
4. **Closure before release / consumer migration** (mostly done):
   - ~~Open-state protocol closure~~
   - ~~Client↔server integration tests (`integration_test.go`)~~
   - ~~Adversarial raw-peer tests (`adversarial_test.go`)~~
   - ~~Localhost TCP suite (`tcp_test.go`)~~
   - ~~Conformance fixtures (`testdata/tp0/`)~~
   - ~~Engine-boundary fuzz (`engine_fuzz_test.go`)~~
   - ~~Leak/race tests (`leak_race_test.go`)~~
   - ~~API review notes + README/API service-first docs~~
   - ~~Benchmarks (`bench_test.go`)~~
   - ~~CI closure-gates job (staticcheck, govulncheck, fuzz seeds)~~
   - ~~Local-replace spikes against go-s7comm / go-mms~~ (ran; see note below — not a green migration)
   - Remaining before RC: real PLC/MMS interoperability; consumer migration design for go-tpkt v1 + TSDU API
5. Expedited / RFC 1006 ED-as-DT remains out of P1 (see design non-goals).

### Local-replace spike results (2026-07-16)

Replacing only `github.com/otfabric/go-cotp` with this tree (then `go mod tidy`) pulls **go-tpkt v1** into consumers. Both **go-s7comm** and **go-mms** still call pre-v1 tpkt APIs (`NewReader(conn)`, `ReadFrame`/`WriteFrame`, `tpkt.Parse`) and therefore **fail to build**. This is expected: migration must move consumers onto the TP0 TSDU service (and drop production go-tpkt), not merely bump the go-cotp module version.

### P2 — migrate consumers, then TP2 / RFC 2126

1. **After** go-cotp RC/v1: migrate go-s7comm off manual CR/DT/TPKT to COTP service (and off go-tpkt).
2. Migrate go-mms off `transport/iso` manual TPKT/COTP.
3. Remove production go-tpkt dependencies from go-s7comm and go-mms.
4. Class 2 state machine, AK/RJ credit, multiplexing.
5. Expedited ED/EA paths and Amendment 1 optional expedited.
6. Explicit vs non-explicit flow control options — **without** changing the consumer TSDU abstraction.

### P3 — complete protocol representation

1. Additional options, QoS / throughput / delay / priority params (beyond P1 preferred-max).
2. Extended formats for DT/ED/AK/EA.
3. Class 4 checksum.
4. Typed reason/cause enumerations.

### P4 — low-value legacy

1. Native CONS/CLNS providers, TP1/TP3/TP4 engines over non-TCP networks.

---

## Current coverage snapshot

| Layer | Coverage |
| --- | --- |
| TPDU codec (10 types) | Implemented with gaps above |
| Protocol engine (TP0 / Class 0 TSDU service) | **Implemented** — `Connect`/`Accept`/`ReadTSDU`/`WriteTSDU`/`Close`; design in [TP0_API_DESIGN.md](TP0_API_DESIGN.md) |
| RFC 1006 / 2126 profile adapter | TP0-over-TPKT via internal go-tpkt; Class 0 only (not full RFC 2126 / TP2) |
| go-tpkt in production package code | **Used inside** `Connect`/`Accept`/`Conn` only; consumers use the TSDU service API |
