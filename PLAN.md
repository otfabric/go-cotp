# go-cotp implementation plan

This plan is derived from [REQUIREMENT.md](REQUIREMENT.md), the X.224/ISO 8073 specs in `spec/`, and integration with [go-tpkt](https://github.com/otfabric/go-tpkt). It is a practical, task-oriented guide—not a substitute for the normative references.

---

## 1. Context and boundaries

### 1.1 Stack position and ecosystem intent

This repository is part of a **curated OT protocol stack under the otfabric namespace**, not generic plumbing for every possible Go ecosystem combination. Boundaries are:

- **go-tpkt** owns RFC 1006 framing.
- **go-cotp** owns X.224 / COTP TPDU parsing and encoding.
- Upper layers (go-s7comm, later go-mms) build on both.

go-cotp is **designed to integrate with the otfabric transport stack**. It is expected to work directly with go-tpkt. It may still decode raw COTP byte slices, but it is **not** trying to support every other transport abstraction or be transport-agnostic for unrelated third-party implementations.

```
TCP
└── TPKT (RFC 1006)     ← go-tpkt
    └── COTP / X.224    ← go-cotp (this repo)
        └── S7comm, MMS, etc.
```

- **go-tpkt** provides: `Encode(payload)`, `Decode(pkt)→payload`, `Reader.ReadFrame()→payload`, `Writer.WriteFrame(payload)`.
- **go-cotp** consumes and produces **COTP payload only**: no TPKT header, no raw TCP. Input to decode = **one complete COTP TPDU payload, typically already extracted from one TPKT frame by go-tpkt** (e.g. the slice returned by `tpkt.Decode` or `tpkt.Reader.ReadFrame`).

### 1.2 Normative references

| Reference | Role |
|-----------|------|
| **ITU-T X.224 (1995)** / **ISO/IEC 8073** | TPDU structure, LI, type codes, fixed/variable part, parameters (Clause 13). |
| **X.224 Amendment 1 (1997)** | Conformance / expedited-data updates. |
| **RFC 1006** | TPKT framing; implemented by go-tpkt, not by go-cotp. |

### 1.3 Wire model (X.224 Clause 13)

- **Octet 1**: Length Indicator (LI). Header length in octets excluding LI and user data; max 254.
- **Octet 2**: TPDU code (and for some types, CDT/options in low bits).
- **Octets 3…**: Fixed part (DST-REF, SRC-REF, CLASS/OPTION, etc.), then variable part (parameters), then optional user data.

TPDU codes (Table 8, 13.2.2.2): CR `1110 xxxx`, CC `1101 xxxx`, DR `1000 0000`, DC `1100 0000`, DT `1111 000y`, ER `0111 0000`, ED `0001 0000`, AK `0110 zzzz`, EA `0010 0000`, RJ `0101 zzzz`.

---

## 2. Scope (from REQUIREMENT.md)

**In scope:** TPDU type definitions; encode/decode; parameter parse/serialize; CR, CC, DT, DR, DC, ER; protocol detection helpers; validation and clear errors.

**Out of scope:** TPKT (use go-tpkt); full application protocols; TCP policy; scanners/fingerprinting logic.

---

## 3. v1 interoperability profile

Define the v1 target explicitly so users do not assume full ISO 8073 behavior:

- **TCP + TPKT carriage** (RFC 1006).
- **Connection-oriented usage** only.
- **TPDUs:** CR, CC, DT, DR, DC, ER.
- **Focus:** OT protocol handoff (S7comm, MMS over TPKT/COTP).
- **Built for the otfabric stack:** go-tpkt → go-cotp → upper protocols.
- **Tested against** S7comm and MMS captures where possible.
- **Not** a full generic OSI transport engine; rare class-specific edge semantics are postponed unless captures prove the need.

---

## 4. Package layout

**Recommended for v1 (simplest):**

```
go-cotp/
├── cotp/           # public API
└── spec/           # normative notes (existing)
```

Optional later: `x224` (constants/naming), `detect` (detection helpers). Prefer a minimal public surface first.

---

## 5. Public API shape

- **Primary:** Public API is **centered on concrete TPDU structs** (CR, CC, DT, DR, DC, ER). An optional small common interface (e.g. `TPDUType() TPDUType`, `MarshalBinary() ([]byte, error)`) may be used only if it genuinely simplifies callers.
- **Do not over-abstract early.** For protocol libraries, concrete structs plus a top-level discriminator often stay simpler. For example:
  - **Option A:** `Decoded struct { Type TPDUType; CR *CR; CC *CC; DT *DT; ...; Raw []byte }`.
  - **Option B:** Small `TPDU` interface only where it clearly helps.
- **Decode:** `Decode([]byte) (Decoded, error)` or equivalent returning a discriminator and concrete pointers; raw decode/encode remains the core primitive.
- **Detection / convenience:** `PeekType`, `LooksLikeCR`, `LooksLikeCC`, `IsConnectionOriented`, `ExtractUserData` are **secondary** to the core wire parsing and marshal/unmarshal API.

---

## 6. Layers inside cotp/

Separate concerns clearly:

| Layer | Responsibility | Examples |
|-------|-----------------|----------|
| **Wire parsing** | LI, fixed part, variable part, bounds | `Decode`, `PeekType`, `ParseParameters` |
| **Typed TPDU structs** | Semantic content; unknown params preserved | `CR`, `CC`, `DT`, … with `Parameters []Parameter` |
| **Marshal / unmarshal** | Struct ↔ bytes | `MarshalBinary`, per-TPDU decode |
| **Helper accessors** | Convenience on top of parsed data | `ExtractUserData`, `LooksLikeCR`, `LooksLikeCC` |

Convenience helpers sit in the same package but are **conceptually secondary**; they do not drive the core design.

---

## 7. Core struct sketches (before implementation)

Define these shapes to avoid churn. Unknown parameters are preserved in a generic slice; do not expose only parsed known fields and discard the raw parameter list.

**Shared:**

```go
type Parameter struct {
    Code  uint8
    Value []byte  // raw value; may alias input
}
```

**CR** (Connection Request): fixed part (CDT, DST-REF, SRC-REF, ClassOption) + variable part as `Parameters []Parameter`. Known params (calling/called selector, TPDU size) can be convenience accessors; full list in `Parameters`.

**CC** (Connection Confirm): same idea—fixed part + `Parameters []Parameter`.

**DT** (Data): fixed part (code/ROA, DST-REF if present, TPDU-NR, EOT) + variable part + user data. v1 focuses on the format commonly seen over RFC 1006/TCP (see §9 and task 1.8).

**DR** (Disconnect Request): fixed part (DST-REF, SRC-REF, Reason) + variable part + optional user data.

**DC** (Disconnect Confirm): fixed part (DST-REF, SRC-REF) + variable part.

**ER** (TPDU Error): fixed part (DST-REF, RejectCause) + variable part (e.g. invalid TPDU param).

Exact field names and types (e.g. `uint16` refs) to be aligned with X.224 Clause 13; the important point is **preserving unknown parameters** for passive decode, replay, and vendor quirks.

---

## 8. Error and validation strategy

- **Sentinels:** `ErrTooShort`, `ErrInvalidLI`, `ErrLengthMismatch` (LI/header/body inconsistency), `ErrUnknownTPDUType`, `ErrInvalidTPDUCode`, `ErrReservedTPDU` (optional, for strict type handling), `ErrMalformedParameter`, `ErrUnexpectedParameterLength`, `ErrUnsupportedTPDU`, `ErrInvalidClassOption`.
- **Wrapping:** Always wrap with context (e.g. "decode CR: invalid LI").
- **Decode:** Reject truncated headers, impossible LI, malformed parameter blocks, length overrun/underflow. Preserve unknown-but-valid where possible.
- **Encode:** Validate required fields and parameter lengths; emit structurally valid TPDUs only.

---

## 9. Strict vs tolerant decode

Document the policy explicitly:

- **Default decoder is strict** on structural invalidity (too short, bad LI, length mismatch, malformed parameters).
- **Unknown parameters** are **tolerated** and preserved (e.g. in `Parameters []Parameter`).
- **Unsupported but structurally valid TPDU types** (e.g. ED, AK, EA, RJ in v1) return **`ErrUnsupportedTPDU`** rather than being silently dropped.

This distinction is important for predictable behavior in scanners and decoders.

---

## 10. Raw preservation policy

For protocol tools, replay, and debug:

- **Decoded structs** represent semantic content plus **preserved unknown parameters**.
- **Malformed packets** return an error and are **not** partially materialized.
- **Optional** full raw retention (e.g. `Raw []byte` on `Decoded`) can be added where needed for replay/debug; define the policy now so replay and debug tooling do not force awkward refactors later.

---

## 11. DT v1 scope (practical OT over TPKT/TCP)

The full X.224 DT spec distinguishes class 0/1 (short fixed part), class 2–4 (DST-REF, TPDU-NR, ROA, EOT, etc.). For v1, **do not implement every class-specific branch** unless captures show the need.

**v1 DT profile:**

- **Full support** for CR and CC.
- **Practical support for DT** as used over TPKT/TCP (e.g. S7comm, MMS): parse the subset actually seen on the wire; preserve raw bytes and unknown fields; reject obviously malformed frames.
- **Postpone** rare class-specific edge semantics (e.g. full class 0 vs 2–4 fixed-part variants) until you have captures that require them.
- Keep **extension points** for broader class handling later (e.g. optional DST-REF, TPDU-NR).

This keeps v1 focused on real OT use cases and avoids spec branches that will not be used soon.

---

## 12. Milestones and task breakdown

### Milestone 1 — Core decode/encode and DT payload

**Goal:** Decode TPDU type; encode/decode CR, CC, DT (practical RFC 1006/TCP OT profile); extract DT user data; preserve unknown parameters; table-driven and fuzz tests; short README and go-tpkt integration examples.

| # | Task | Notes |
|---|------|--------|
| 1.1 | **Repository bootstrap and go-tpkt integration** | `go.mod` (Go 1.22+), `cotp/` package, `internal/` if desired. **Add dependency `github.com/otfabric/go-tpkt`.** Provide **first-class helpers** for `tpkt.Reader` / `tpkt.Writer` workflows (e.g. wrap read-frame-then-decode, write-encode-then-frame). Keep **raw `[]byte` decode/encode as the core primitive** underneath. Include **examples and tests** that use `tpkt.Reader` / `tpkt.Writer`. |
| 1.2 | **Errors** | Define sentinel errors in `cotp/errors.go` (including `ErrLengthMismatch`; optionally `ErrInvalidTPDUCode`, `ErrReservedTPDU`). |
| 1.3 | **TPDUType and PeekType** | Enum of type codes; `PeekType(b []byte) (TPDUType, error)` using LI + octet 2; reject too-short, invalid LI. |
| 1.4 | **LI and header bounds** | Helper to read LI, validate (e.g. LI ≤ 254, LI + 1 + user data ≤ len(b)). Reject if header length exceeds buffer. |
| 1.5 | **CR decode** | Parse fixed part (octets 2–7): code, CDT, DST-REF, SRC-REF, CLASS/OPTION. Parse variable part (octets 8..p): parameter code + length + value; implement calling/called transport selector (0xC1, 0xC2), TPDU size (0xC0), and **preserve unknown params in `Parameters`**. |
| 1.6 | **CR encode** | Build CR from struct; validate required fields; emit canonical CR. |
| 1.7 | **CC decode/encode** | Same pattern as CR (fixed part 2–7, variable part); DST-REF, SRC-REF, CLASS/OPTION; same parameter set; preserve unknown in `Parameters`. |
| 1.8 | **DT decode** | **Parse DT as seen in RFC 1006/TCP OT use cases first** (practical v1 profile). Fixed part: DT code + ROA, DST-REF if present, TPDU-NR, EOT. Variable part if present. User data = rest. **Keep extension points** for broader class handling (e.g. class 0/1 vs 2–4) later; do not implement every spec branch in v1. |
| 1.9 | **DT encode** | Build DT from struct; optional DST-REF, TPDU-NR, EOT; user data. |
| 1.10 | **Extract user data** | `ExtractUserData(b []byte) ([]byte, error)` for DT (and later ED if needed); use PeekType + DT parser. |
| 1.11 | **Decode return type** | `Decode(b []byte) (Decoded, error)` (or equivalent) with concrete struct pointers (CR, CC, DT, …) and `Type TPDUType`; avoid forcing a large interface until it clearly simplifies callers. |
| 1.12 | **Round-trip tests** | Table-driven: valid minimal/common CR, CC, DT; malformed (too short, bad LI, length mismatch); unknown parameter; unsupported TPDU. |
| 1.13 | **Fuzz tests** | Fuzz `Decode`, `DecodeCR`, `DecodeCC`, `DecodeDT`; no panics, no OOB, deterministic errors. |
| 1.14 | **README and examples** | Example: read TPKT frame via `tpkt.Reader.ReadFrame()`, `cotp.Decode(payload)`, then switch on type / extract DT payload. Demonstrate first-class go-tpkt integration. |

**Spec refs:** X.224 Clause 13.2 (structure, LI, variable part), 13.3 (CR), 13.4 (CC), 13.7 (DT).

---

### Milestone 2 — DR, DC, ER and detection

**Goal:** DR/DC/ER encode/decode; detection helpers; canonical parameter types; golden vectors.

| # | Task | Notes |
|---|------|--------|
| 2.1 | **DR decode/encode** | Fixed part: DR code, DST-REF, SRC-REF, REASON. Variable part (e.g. 0xE0 additional info, checksum). User data optional (≤64 octets). |
| 2.2 | **DC decode/encode** | Fixed part: DC code, DST-REF, SRC-REF. Variable part: checksum if class 4. |
| 2.3 | **ER decode/encode** | Fixed part: ER code, DST-REF, REJECT CAUSE. Variable: invalid TPDU (0xC1), checksum. |
| 2.4 | **Detection helpers** | `LooksLikeCR`, `LooksLikeCC`, `IsConnectionOriented` (e.g. CR/CC/DR/DC), `ExtractUserData` (already in M1). Lightweight, no allocation where possible. |
| 2.5 | **Canonical parameter types** | Shared types for transport selectors, TPDU size, class/option; reuse in CR/CC. |
| 2.6 | **Pretty-print / debug** | Optional `String()` or debug dump for TPDUs. |
| 2.7 | **Golden tests** | Hex vectors for real S7comm CR/CC over TPKT (and MMS-style if available). |

**Spec refs:** X.224 13.5 (DR), 13.6 (DC), 13.12 (ER).

---

### Milestone 3 — Optional TPDUs and polish (post-v1)

**Goal:** ED, AK, EA, RJ when needed; more interop vectors; passive decoder and handoff examples.

This milestone is **optional and post-v1**. If the next consumers (go-s7comm, go-mms) do not need ED/AK/EA/RJ immediately, defer this work until captures or requirements justify it.

| # | Task | Notes |
|---|------|--------|
| 3.1 | **ED decode/encode** | Fixed part: ED code, DST-REF, ED-TPDU-NR, EOT; variable (checksum); user data 1–16 octets. |
| 3.2 | **AK decode/encode** | Fixed: AK, CDT, DST-REF, YR-TU-NR; variable (e.g. checksum, subsequence, flow control confirmation). |
| 3.3 | **EA decode/encode** | Fixed: EA, DST-REF, YR-EDTU-NR; variable (checksum). |
| 3.4 | **RJ decode/encode** | Fixed: RJ, CDT, DST-REF, YR-TU-NR; no variable part. |
| 3.5 | **Interop vectors** | More golden files from captures (S7, MMS, other OT). |
| 3.6 | **Passive decoder / handoff** | Helpers or examples: read TPKT → COTP decode → hand off DT payload to S7/MMS layer. |

**Spec refs:** X.224 13.8 (ED), 13.9 (AK), 13.10 (EA), 13.11 (RJ).

---

## 13. Integration with go-tpkt

- **Mandatory dependency:** go-cotp **depends on** `github.com/otfabric/go-tpkt` as part of the otfabric stack design. No attempt to be transport-agnostic for unrelated implementations.
- **Typical server/client:** Use `tpkt.NewReader(conn)` and `tpkt.NewWriter(conn)`. Call `r.ReadFrame()` to get one TPDU payload; pass to `cotp.Decode(payload)`. Send by building CR/CC/DT with cotp, then `w.WriteFrame(marshaled)`. First-class helpers can wrap this pattern.
- **Single-packet decode:** `raw, _ := tpkt.Decode(tcpPacket)` then `msg, err := cotp.Decode(raw)`.
- **Sizing:** go-tpkt allows payloads ≥ 3 octets (RFC 1006 min 7 = 4 header + 3 TPDU). COTP minimum TPDU is 2 octets (LI + type code); enforce in cotp that decoded length is consistent with LI.

---

## 14. Hex fixture and test data policy

Define up front where real vectors and fixtures live:

- **`testdata/frames/*.hex`** — Raw COTP (or TPKT+COTP) hex dumps for golden decode tests.
- **`testdata/pcap/*.pcap`** (optional) — Captures for extraction of frames and future interop tests.
- **`testdata/json/*.golden.json`** (optional) — Expected decoded structure for golden comparison.

This keeps test data consistent and makes it easy to add S7comm/MMS captures later.

---

## 15. Testing checklist (from REQUIREMENT.md)

- **Unit:** TPDU type detection; CR/CC/DT/DR/DC/ER decode; parameter parsing; encode/decode round trips; truncated and malformed inputs.
- **Table-driven:** Valid minimal, valid common, malformed short, malformed length mismatch, unknown parameter, unsupported TPDU.
- **Fuzz:** Decode entrypoints; no panics, no OOB, deterministic errors.
- **Golden:** Real S7comm/MMS COTP handshakes where possible.

---

## 16. Non-goals for v1

- Full X.224 class/option semantics and state machines.
- Expedited data behavior beyond wire format.
- Every rare TPDU; focus on CR, CC, DT, DR, DC, ER first.
- Implementing TPKT (use go-tpkt).
- Full generic OSI transport engine; v1 is built for the otfabric stack and practical OT handoff.

---

## 17. Suggested implementation order (Milestone 1)

1. Bootstrap repo, add go-tpkt dependency, define errors.
2. LI + PeekType + TPDUType.
3. Parameter parser (code + length + value; known + unknown → `Parameter` / `Parameters`).
4. Core struct sketches (Parameter, CR, CC, DT) and raw preservation in types.
5. CR (decode then encode).
6. CC (decode then encode).
7. DT (decode then encode, v1 practical profile); ExtractUserData.
8. Decode() → Decoded (or chosen return shape).
9. First-class tpkt.Reader/Writer helpers and examples.
10. Table-driven and fuzz tests.
11. README with go-tpkt + cotp example.

This order keeps each step testable and avoids big-bang integration.
