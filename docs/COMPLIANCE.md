# go-cotp Standards Compliance

**Status date:** 2026-07-16  
**Module:** `github.com/otfabric/go-cotp`  
**Framing dependency:** `github.com/otfabric/go-tpkt` v1.0.0  

## Safe compliance claim

> **X.224 TPDU codec** with encode/decode support for all ten connection-oriented TPDU type codes (CR, CC, DR, DC, DT, ED, AK, EA, RJ, ER), suitable for use with RFC 1006 / RFC 2126 TPKT framing via go-tpkt. **Not** a complete X.214 transport service, **not** a complete X.224 protocol engine, and **not** RFC 2126 / ITOT compliant as a transport implementation.

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

**Classification of this repository:** **codec only** — no X.214 service API.

| ID | Requirement | Source | Clause | Basis | Current code | Tests | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A-01 | T-CONNECT request/indication/response/confirm | X.214 | §12–13 service primitives (p.~table of primitives) | ITU normative | — | — | not implemented | No Connect/Accept API |
| A-02 | T-DATA request/indication | X.214 | Data transfer primitives | ITU normative | DT codec only | decode/encode DT | partial | Wire DT exists; no TSDU segmentation service |
| A-03 | T-EXPEDITED-DATA | X.214 | Expedited data primitives | ITU normative | ED/EA codec | ED tests | partial | Codec only; no service queueing |
| A-04 | T-DISCONNECT | X.214 | Release primitives | ITU normative | DR/DC codec | DR/DC tests | partial | No release state machine |
| A-05 | Transport addresses / selectors | X.214 | Addressing | ITU normative | `CallingSelector`/`CalledSelector` raw `[]byte` | CR/CC param tests | partial | No semantic TSAP type |
| A-06 | QOS negotiation | X.214 | QOS parameters | ITU normative | — | — | not implemented | Throughput/delay/etc. not modeled |
| A-07 | Error / disconnect indications to TS-user | X.214 | Provider-initiated release | ITU normative | ER reason fields as wire | ER tests | not implemented | No indication delivery API |

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
| B-07 | Unknown parameter in non-CR: protocol error | X.224 | 13.2.3 (p.57) | ITU normative | preserved in `Parameters` | — | **fail** / implementation choice | Current codec preserves unknowns on all types for replay; stricter engine must reject |
| B-08 | Duplicate parameter: last value wins | X.224 | 13.2.3 (p.57) | ITU normative | `parseCRCCVariablePart` | params / p0 tests | pass | Known CR/CC params: last wins; unknown params: all preserved |
| B-09 | Parameter order arbitrary | X.224 | 13.2.3 (p.57) | ITU normative | decode any order; encode CR/CC canonical C1→C2→C0 | encode tests | partial | Canonical order is **local deterministic policy**, not X.224-mandated |
| B-10 | Transport references DST/SRC | X.224 | 13.3–13.6 | ITU normative | fields on CR/CC/DR/DC/… | unit tests | pass | Wire fields only; no allocation/validation engine |
| B-11 | Class and option negotiation | X.224 | 6.5, 13.3.3 | ITU normative | `ClassOption` octet stored | — | not implemented | No negotiation; value not validated (`ErrInvalidClassOption` unused) |
| B-12 | Alternative protocol classes | X.224 | 6.5 / CR variable part | ITU normative | unknown param only | — | not implemented | No typed param |
| B-13 | TPDU size parameter (0xC0) | X.224 | 13.3.4 b) | ITU normative | `TPDUSize *uint8` | CR/CC tests | partial | Length=1 enforced; legal size codes (7–13) **not** validated; negotiation absent |
| B-14 | Preferred maximum TPDU size | X.224 | 13.3.4 c), 6.5 | ITU normative | — | — | not implemented | Distinct from 0xC0 |
| B-15 | Calling/Called TSAP selectors | X.224 | 13.3.4 a) | ITU normative | `0xC1`/`0xC2` typed | params / p0 tests | partial | Raw bytes; encode rejects len>255; semantic TSAP type still absent |
| B-16 | Checksum parameter (class 4) | X.224 | 13.2.3.1, 6.17 | ITU normative | — | — | not implemented | |
| B-17 | Additional option selection | X.224 | 13.3.4 / 6.5 | ITU normative | unknown param only | — | not implemented | Includes expedited negotiation |
| B-18 | Ack time, throughput, residual error, priority, transit delay, reassignment, inactivity | X.224 | 13.3.4 | ITU normative | — | — | not implemented | |
| B-19 | User data in CR/CC | X.224 | 13.3 / 6.5 | ITU normative | `CR.UserData` / `CC.UserData` | `p0_test.go` | pass | Exposed and round-tripped; CR total ≤128 enforced |
| B-20 | Error / reason codes | X.224 | DR reason, ER reject cause | ITU normative | `Reason`, `RejectCause` uint8 | DR/ER tests | partial | Enumerations not validated |

---

## C. TPDU formats

| ID | TPDU | Requirement | Source | Clause | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| C-CR | CR | Fixed part CDT/DST/SRC/ClassOption + var params | X.224 | 13.3 (p.57+) | pass / partial | Typed C1/C2/C0; UserData; CR≤128; many optional CR params still untyped |
| C-CC | CC | Same family as CR | X.224 | 13.4 | pass / partial | Same as CR minus 128-octet cap |
| C-DR | DR | Refs, reason, params, user data | X.224 | 13.5 | partial | User data exposed; ≤64-octet limit not enforced |
| C-DC | DC | Refs + params | X.224 | 13.6 | partial | Trailing octets ignored |
| C-DT | DT | Minimal (class 0/1) and normal; extended optional | X.224 | 13.7 | partial | Minimal LI=2 + normal LI≥4; **extended rejected** (`ErrUnsupportedDTVariant`); ROA bit not modeled on encode (always 0) |
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
| E-02 | Class 0 over TCP | RFC 1006 | body | RFC normative | not implemented | No TP0 engine |
| E-03 | One TC ↔ one TCP connection | RFC 1006 | mapping | RFC normative | not implemented | |
| E-04 | TCP stream ≠ TPDU boundary | RFC 1006 | TPKT | RFC normative | pass (dependency) | go-tpkt `ReadPacket` |
| E-05 | Port 102 | RFC 1006 | Status / § | RFC normative | not applicable | Profile concern, not codec |
| E-06 | Default max TPDU 65531 | RFC 1006 | TPKT length | RFC normative | documentation gap | Relation to `TPDUSize` / ReaderConfig not documented in go-cotp |
| E-07 | Expedited: modified ED ≈ DT | RFC 1006 | expedited notes | RFC normative | **unclear** / partial | Library ED follows X.224 13.8 shape (DST-REF + NR), not the RFC 1006 “ED looks like DT” experimental form |
| E-08 | TCP close → disconnect | RFC 1006 | mapping | RFC normative | not implemented | |

---

## F. RFC 2126 ITOT profile

| ID | Requirement | Source | Clause | Basis | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| F-01 | Class 0 over TCP | RFC 2126 | §4.1 | RFC normative | not implemented | Codec only |
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

Both justified: `Decode` for demux; `Decode*` for engine paths that already know the type. Shared path is PeekType → Decode*. Divergence risk exists (`DecodeDT` accepts wider type mask than `PeekType`).

### 3.3 `MarshalBinary`

Implements `encoding.BinaryMarshaler`. Canonical CR/CC parameter order is a **local deterministic encoding choice**, not an X.224 rule. Unknown params after known typed fields. Typed fields win over duplicate codes in `Parameters`.

### 3.4 `LooksLike*`

Classification-only; **must never be presented as validation**. `LooksLikeDT` uses the same `0xFE` mask as `PeekType`/`DecodeDT` (0xF0–0xF1).

### 3.5 Error model

| Sentinel | Issue |
| --- | --- |
| `ErrLengthMismatch` | Unused |
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

### P0 — codec correctness / security — **done**

1. ~~Enforce `LI ≥ fixed-part length` (X.224 13.2.2.1).~~
2. ~~Fix CR/CC selector encode length >255 (error, not truncate).~~
3. ~~Align `LooksLikeDT` mask with `PeekType` / `Decode`.~~
4. ~~CR/CC user-data: expose and round-trip; CR total ≤128.~~
5. ~~Duplicate known params: X.224 last-wins; documented.~~

### P1 — freeze TP0 service API, then implement TP0 engine

1. Design and freeze X.214-style service API (`Client`/`Server`/`Conn` Read/Write/Disconnect) from S7comm + MMS requirements.
2. Connection state machine (Annex A class 0).
3. CR/CC negotiation (class, TPDU size, selectors as opaque bytes).
4. DT segmentation / reassembly (EOT) → complete TSDUs.
5. DR/DC/ER handling and TCP close mapping.
6. RFC 1006 adapter inside go-cotp using go-tpkt (exclusive production import).
7. Clarify RFC 1006 ED-vs-DT expedited encoding vs X.224 ED.

### P2 — migrate consumers, then TP2 / RFC 2126

1. Migrate go-s7comm off manual CR/DT/TPKT to COTP service.
2. Migrate go-mms off `transport/iso` manual TPKT/COTP.
3. Remove production go-tpkt dependencies from go-s7comm and go-mms.
4. Class 2 state machine, AK/RJ credit, multiplexing.
5. Expedited ED/EA paths and Amendment 1 optional expedited.
6. Explicit vs non-explicit flow control options — **without** changing the consumer TSDU abstraction.

### P3 — complete protocol representation

1. Preferred max TPDU size, additional options, QoS params.
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
| Protocol engine (X.214 TSDU service) | **None** — target in ARCHITECTURE.md |
| RFC 1006 / 2126 profile adapter | Framing used in examples/tests only; not owned as Conn composition yet |
| go-tpkt in production package code | **None** (examples + tests only) — correct until engine lands |
