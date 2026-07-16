# TP0 Service API Design (P1)

**Status:** architecture **frozen**; public API **frozen**; negotiation **implementation-frozen**  
**Date:** 2026-07-16 (rev. 7.1 + negotiation impl)  
**Scope:** RFC 1006 / RFC 2126 Class 0 (TP0) over TPKT via go-tpkt  
**Related:** [ARCHITECTURE.md](ARCHITECTURE.md), [COMPLIANCE.md](COMPLIANCE.md), [API.md](API.md)

**Core abstraction:** an established COTP connection that reads and writes **complete TSDUs**.

```
go-s7comm / go-mms
        ↓ complete TSDUs
go-cotp TP0 service
        ↓ COTP TPDUs
go-tpkt
        ↓
TCP or TLS
```

Do **not** reopen the overall architecture unless implementation exposes a concrete contradiction.

---

## Verdict (rev. 7.1 + negotiation impl)

| Area | Status |
| --- | --- |
| Architecture | **Frozen** |
| Public service abstraction | **Frozen** |
| Naming / ownership / TSDU API | **Frozen** |
| Negotiation and handshake rules | **Fully specified** |
| Typed Preferred Maximum (`0xF0`) codec + cases 1–60 | **Implemented and green** |
| TP0 connection core + client `Connect` handshake | **Implemented and green** |
| Server `Accept` handshake | **Implemented and green** |
| Single-DT `ReadTSDU` / `WriteTSDU` | **Implemented and green** |
| Segmentation / reassembly | **Implemented and green** |
| Open-state protocol-error coverage | **Implemented and green** |
| Consumer migrations (S7, then MMS) | **Next** |

> Architecture frozen · public API frozen · negotiation implementation-frozen

Begin the TP0 engine next (§14 after cases 1–60).

---

## 1. Ownership boundaries

| Concern | Owner |
| --- | --- |
| TPKT framing | **go-cotp** internally via **go-tpkt** (not in public config) |
| CR/CC handshake | **go-cotp** |
| References | **go-cotp** |
| Class 0 accept/reject | **go-cotp** |
| TPDU-size / preferred-max negotiation | **go-cotp** |
| DT segmentation / reassembly | **go-cotp** |
| TP0 release via TCP close; DR for CR refuse / selected errors | **go-cotp** |
| Opaque selectors | **go-cotp** transports; policy as configured |
| Siemens TSAP / rack/slot | **go-s7comm** |
| S7 Setup Communication / S7 PDU size | **go-s7comm** |
| Session / Presentation / ACSE / MMS | **go-mms** |
| TCP dial, TLS, reconnect, discovery | **consumer** |

### Dependency invariants

1. Only go-cotp imports go-tpkt in production stack code.
2. Consumers use `*cotp.Conn` TSDUs; no CR/CC/DT in normal paths.
3. Selectors are opaque `[]byte`.
4. Public config: COTP limits only (`MaxTPDULength`, `MaxTSDULength`) — never TPKT knobs.
5. `Connect` / `Accept` take ownership of `net.Conn` **immediately** on entry.

### Connect data (profile scope)

**RFC 1006 / RFC 2126 ITOT profile** permits initial CR/CC user data as a deliberate exception / testing extension relative to standard Class 0.

**Generic X.224 Class 0** does **not** make connection-establishment user data available when Class 0 is the preferred class.

Therefore:

> Connect data is supported by the RFC 1006 / RFC 2126 TP0-over-TCP profile. It must not be assumed available in every future Class 0 network profile.

Expose it on the ITOT TP0 service API; never silently discard it.

---

## 2. Public API

### Lifecycle

```go
func Connect(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Conn, error)
func Accept(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Conn, error)

// Optional later:
func Dial(ctx context.Context, network, address string, cfg ClientConfig) (*Conn, error)
```

### Ownership (settled)

`Connect` / `Accept` own `conn` immediately. On any error they close `conn`. Caller must not use it further after a failed call.

**Preflight:** validate all locally knowable conditions **before** writing a CR or reading a CR, so bad local config emits **zero protocol bytes** (connection is still closed per ownership). See §2.1.

### Configuration

```go
type ClientConfig struct {
    LocalSelector  []byte // calling; nil = omit; non-nil empty = present len 0
    RemoteSelector []byte // called; same nil/empty rules
    // MaxTPDULength is the local configured ceiling (octets, including header).
    // Zero means DefaultMaxTPDULength (65531). Wire encoding may yield a lower
    // negotiated maximum (preferred-max granularity / peer selection).
    // Values in (0, 128) or > 65531 → ErrInvalidConfig (no silent clamp).
    MaxTPDULength int
    // MaxTSDULength is a symmetric local service policy bound:
    //   - maximum TSDU accepted by WriteTSDU;
    //   - maximum TSDU reassembled by ReadTSDU.
    // Zero = DefaultMaxTSDULength (4 MiB). Negative → ErrInvalidConfig.
    // Need not be ≥ MaxTPDULength.
    MaxTSDULength int
    // ConnectData is RFC 1006/ITOT connection-establishment user data in CR.
    // It is not part of generic X.224 Class 0 behavior.
    // Length must be ≤ MaxConnectDataLength (32). Resulting CR must also be
    // ≤ MaxCRTPDULength (128). No silent truncation.
    ConnectData []byte
    // SizeProfile selects local CR/CC size-parameter encoding and how omitted
    // peer selections are interpreted. Zero = SizeProfileRFC1006Compat.
    // Unknown values → ErrInvalidConfig before protocol I/O.
    SizeProfile SizeProfile
}

type ServerConfig struct {
    // LocalSelector default accept policy (§4):
    //   nil            → no called-selector requirement
    //   non-nil empty  → CR must present CalledSelector of length 0
    //   non-empty      → CR must present CalledSelector equal exactly
    LocalSelector []byte
    MaxTPDULength int // same validation rules as ClientConfig
    MaxTSDULength int // same symmetric rules as ClientConfig
    // OnConnect decides accept/reject. Nil = defaultAutoAccept (§4).
    // Indication fields are defensive copies (safe to retain).
    OnConnect func(context.Context, ConnectIndication) (AcceptDecision, error)
    // SizeProfile governs CC encoding and omitted-size acceptance policy (§5.6–§5.8).
    // Unknown values → ErrInvalidConfig. CR parser always accepts valid 0xC0/0xF0.
    SizeProfile SizeProfile
}

type SizeProfile int

const (
    SizeProfileRFC1006Compat SizeProfile = iota
    SizeProfilePreferredMaximum
    // values outside this set → ErrInvalidConfig
)

const (
    DefaultMaxTPDULength  = 65531
    DefaultMaxTSDULength  = 4 * 1024 * 1024
    MaxITOTTPDULength     = 65531
    MinTPDULength         = 128
    MaxPreferredUnitsITOT = 511 // ITOT service only; not a generic codec limit
    // MaxConnectDataLength is the ITOT-profile service ceiling for CR/CC
    // connection-establishment user data (aligned with X.224's 32-octet
    // establishment-data limit for classes that support it). RFC 1006 adds
    // the connect-data exception for Class 0 over TCP; the 32-octet bound
    // is the frozen public contract. CR total length ≤ 128 still applies.
    MaxConnectDataLength = 32
)

type ConnectIndication struct {
    CallingSelector []byte // copy
    CalledSelector  []byte // copy
    ProposedClass   Class
    // MaxTPDULength is the ceiling presented to connection policy.
    // When Preferred is present, this is the preferred offer.
    // OnConnect cannot choose between the Standard and Preferred negotiation
    // paths; SizeProfile and the engine's selection policy own that choice.
    // The engine retains the dual offer internally for path selection (§5.5).
    MaxTPDULength int
    ConnectData   []byte // copy of CR user data (ITOT profile)
    SourceRef     uint16
}

type ConnectAction uint8

const (
    ConnectReject ConnectAction = iota // zero value = reject (safe default)
    ConnectAccept
    // other values → invalid callback result (§4.2)
)

type AcceptDecision struct {
    Action ConnectAction
    // MaxTPDULength is an additional policy ceiling when non-zero.
    //
    // The ceiling is normalized to the selected wire path before selection:
    // preferred path uses floor-to-128; standard path uses the largest
    // Class-0 standard TPDU size not exceeding the ceiling.
    //
    // A higher ceiling than the current selection has no effect.
    // Zero means no additional ceiling. See §5.7 — do not use a raw integer min.
    MaxTPDULength int
    // ConnectData is ITOT CC user data; length ≤ MaxConnectDataLength (32).
    // No silent truncation. Also subject to CC header limits.
    ConnectData   []byte
    RejectReason  DisconnectReason // meaningful only when Action == ConnectReject
}

type Class uint8

const Class0 Class = 0

// DisconnectReason is an X.224 DR reason code (X.224 §13.5.3).
type DisconnectReason uint8

// Values usable for all classes (including Class 0):
const (
    ReasonNotSpecified       DisconnectReason = 0 // default when ConnectReject leaves RejectReason unset
    ReasonCongestionAtTSAP   DisconnectReason = 1
    ReasonSessionNotAttached DisconnectReason = 2
    ReasonAddressUnknown     DisconnectReason = 3
)

// Values primarily defined for classes 1–4; usable on DR during TP0 refusal
// when they describe the failure accurately (X.224 §13.5.3, 128+n table):
const (
    ReasonNormalDisconnect          DisconnectReason = 128 // 128+0
    ReasonRemoteCongestion          DisconnectReason = 129 // 128+1
    ReasonNegotiationFailed         DisconnectReason = 130 // 128+2 proposed class(es) not supported
    ReasonDuplicateSourceReference  DisconnectReason = 131 // 128+3
    ReasonMismatchedReferences      DisconnectReason = 132 // 128+4
    ReasonProtocolError             DisconnectReason = 133 // 128+5
    ReasonReferenceOverflow         DisconnectReason = 135 // 128+7
    ReasonRefusedOnNetworkConn      DisconnectReason = 136 // 128+8
    ReasonInvalidHeaderOrParamLen   DisconnectReason = 138 // 128+10
)

// Default DR reason mappings for P1 handshake refusals (§4.2 / §3–§6):
//
// | Rejection                                      | DR reason                      |
// | ---------------------------------------------- | ------------------------------ |
// | Default callback rejection (ReasonNotSpecified)| ReasonNotSpecified (0)         |
// | Called selector absent/mismatched              | ReasonAddressUnknown (3)       |
// | Unsupported proposed class                     | ReasonNegotiationFailed (130)  |
// | Invalid header or parameter length             | ReasonInvalidHeaderOrParamLen (138) |
// | Duplicate source reference (if detectable)     | ReasonDuplicateSourceReference (131) |
// | Other identifiable protocol error              | ReasonProtocolError (133)      |

// NegotiatedParameters are frozen after successful CR/CC.
// Local*/Remote* are from this endpoint's perspective.
// Selector nil means parameter absent; non-nil empty means present len 0.
// All slices are defensive copies.
type NegotiatedParameters struct {
    Class          Class
    MaxTPDULength  int
    LocalRef       uint16
    RemoteRef      uint16
    LocalSelector  []byte
    // RemoteSelector is the effective peer selector:
    //   CC responding/called selector when present, otherwise the requested
    //   ClientConfig.RemoteSelector (client) / peer CR calling selector (server).
    RemoteSelector  []byte
    PeerConnectData []byte // ITOT peer connect data; not a size parameter
}
```

**No public TPKT configuration.** Internally use `tpkt.MaxPacketLength` (65535) for the reader during handshake; enforce negotiated COTP `MaxTPDULength` after Open.

### 2.1 Preflight (before protocol I/O)

Validate before writing CR / reading CR:

| Condition | Error |
| --- | --- |
| `MaxTPDULength` in `(0,128)` or `>65531` | `ErrInvalidConfig` |
| `MaxTSDULength < 0` | `ErrInvalidConfig` |
| unknown `SizeProfile` | `ErrInvalidConfig` |
| any selector length > 255 | `ErrInvalidConfig` (or wrap encode length error) |
| `ConnectData` length > `MaxConnectDataLength` (32) | `ErrInvalidConfig` |
| `ConnectData` making CR > 128 octets | `ErrInvalidConfig` |
| other callback-independent server config invalid | `ErrInvalidConfig` |

Ownership still closes `conn` on these errors; no CR/CC bytes are emitted.

### Conn

```go
type Conn struct { /* unexported */ }

func (c *Conn) ReadTSDU(ctx context.Context) ([]byte, error)
func (c *Conn) WriteTSDU(ctx context.Context, tsdu []byte) error

// Close performs TP0 T-DISCONNECT by closing the underlying stream.
// Idempotent on a non-nil Conn. Nil-receiver Close is not promised.
func (c *Conn) Close() error

func (c *Conn) Negotiated() NegotiatedParameters
func (c *Conn) LocalAddr() net.Addr
func (c *Conn) RemoteAddr() net.Addr
```

**`Disconnect` is not part of the P1 API.**

`WriteTSDU`: if `len(tsdu) == 0` → `ErrEmptyTSDU`; if `len(tsdu) > maxTSDULength` → `ErrTSDUTooLarge` **before** protocol I/O; Conn remains usable.

### Package layout

P1: codec + service in root `cotp`. Do not relocate codecs while implementing the engine.

Size negotiation is an **internal pure-function component** (§5.9).

---

## 3. State machine (TP0 over TCP)

| State | Meaning |
| --- | --- |
| `connecting` | CR sent; waiting for CC/refusal |
| `accepting` | CR received; policy / CC pending |
| `open` | data transfer |
| `closing` | local `Close` in progress |
| `closed` | orderly stream closure |
| `aborted` | protocol / framing / context / network failure |

Successful `Connect` / `Accept` return `*Conn` in **`open`**. Internal states are not exported on typed public errors (see §8).

### 3.1 References (frozen)

X.224: each entity’s selected connection reference shall not be zero and shall not already be in use or frozen.

**Allocator (process-wide, collision-safe):**

A monotonically incrementing `uint16` alone is insufficient (wrap can collide with live connections). Use a reusable process-wide allocator:

- mutex;
- active-reference set;
- next candidate;
- skip zero;
- skip references currently active;
- release exactly once on terminal connection cleanup.

This satisfies X.224 entity-wide uniqueness for TP0 and remains a foundation for future TP2. Do **not** claim entity-wide uniqueness if allocating only per-TCP-connection without documenting that TP0’s 1:1 TC↔TCP mapping is the sole uniqueness scope.

**Accept (incoming CR):**

| Field | Rule |
| --- | --- |
| `CR.DST-REF` | must equal `0` |
| `CR.SRC-REF` | must **not** equal `0` |

Failure → handshake/protocol error (send ER when identifiable as Class 0 CR, else close).

**Connect (incoming CC):**

| Field | Rule |
| --- | --- |
| `CC.DST-REF` | must equal our `CR.SRC-REF` |
| `CC.SRC-REF` | must **not** equal `0` |

Failure → handshake failure.

Do **not** silently accept zero peer references in the default engine. An `AllowZeroPeerReference` compatibility option is out of P1 until a real consumer demonstrates need.

Wire roles:

- CR: `DST-REF = 0`, `SRC-REF = allocate()`.
- CC: `DST-REF = CR.SRC-REF`, `SRC-REF = allocate()`.

### Release (settled)

RFC 1006: N-DISCONNECT.REQUEST = close TCP.  
RFC 2126: Class 0 has no explicit transport disconnection; DR/DC explicit release is Class 2.

```
open ──Close──► closing ──► closed
         └── prevent new ops; unblock waiters; close stream
```

**DR usage:**

| Situation | Action |
| --- | --- |
| `connecting` + DR | refused → `ErrConnectionRefused` + `RejectionError` |
| `accepting` + policy reject | send DR, then close |
| `open` + DR | unexpected → close; `ErrUnexpectedTPDU` + `ErrDisconnected` |
| Do **not** answer open-state DR with DC in TP0 | |

### Unexpected / error responses (P1)

| Situation | P1 action |
| --- | --- |
| Invalid parseable CR identifying Class 0 | send ER when possible, then close |
| Valid CR rejected by policy | send DR, then close |
| Malformed CR that cannot be safely associated | close |
| Unexpected TPDU after Open | close and abort |
| Malformed DT after Open | close and abort |
| TPKT/framing error | close and abort |

### TCP EOF and close classification (settled)

| Cause | Error classification |
| --- | --- |
| Peer orderly EOF | `ErrDisconnected` + `io.EOF` |
| Peer reset / network failure | `ErrDisconnected` + underlying network error |
| Local `Close()` waking blocked ops | `ErrClosed` (typically also `net.ErrClosed`); **not** `ErrDisconnected` |
| Context expiry/cancel after I/O started | `ErrClosed` + `ctx.Err()` |
| EOF mid-TSDU reassembly | `ErrIncompleteTSDU` + `ErrDisconnected` + `io.EOF` |

---

## 4. Server accept policy

1. Preflight server config (§2.1).
2. Parse CR → dual size offer retained; validate Class 0 fixed fields (§6.1) and references (§3.1); build `ConnectIndication` (defensive copies).
3. `OnConnect == nil` → `defaultAutoAccept`:
   - Class 0 only (else reject).
   - **Selector policy:**
     - `LocalSelector == nil` → do not require a called selector.
     - `LocalSelector != nil` → CR **must** contain `CalledSelector` equal **exactly** (including zero-length). Absent or unequal → reject as address unknown.
   - Accept with default size selection.
4. Else call `OnConnect` (§4.2).
5. Reject → DR + close + error.
6. Accept → `selectSize` (§5.7) → encode CC (§5.6) → return open `Conn`.

### 4.1 Client-side CC selector validation

| Condition | Action |
| --- | --- |
| CC contains responding/called selector **and** `ClientConfig.RemoteSelector` was present | returned selector **must equal** `RemoteSelector`; mismatch → handshake failure |
| CC omits the selector | accept (echo optional) |
| `ClientConfig.RemoteSelector` was absent | retain any returned selector as peer metadata |

`NegotiatedParameters.RemoteSelector`: returned CC selector when present, otherwise requested `ClientConfig.RemoteSelector`.

### 4.2 Callback and enum contracts

| Result | Behavior |
| --- | --- |
| unknown `ClientConfig`/`ServerConfig`.`SizeProfile` | `ErrInvalidConfig` before protocol I/O |
| `OnConnect` returns non-nil error | do **not** invent a DR reason; close connection; return error wrapping callback error and `ErrHandshake` |
| `OnConnect` returns unknown `ConnectAction` | close; local accept-policy / config error (wrap `ErrInvalidConfig` or dedicated policy error + `ErrHandshake`) |
| `ConnectReject` with zero/`ReasonNotSpecified` `RejectReason` | send DR with `ReasonNotSpecified` |
| `ConnectAccept` with `RejectReason` set | **ignore** `RejectReason` |
| `ConnectAccept` with `ConnectData` length > 32 | policy/handshake error before CC write; close |

A callback error is a local server failure, not necessarily a valid peer rejection reason.

---

## 5. TPDU-size negotiation

### 5.1 Configured vs negotiated

| Value | Meaning |
| --- | --- |
| config `MaxTPDULength` | Local **configured ceiling** |
| `NegotiatedParameters.MaxTPDULength` | **Effective** maximum after path selection |

| Configured | Result |
| --- | --- |
| `0` | treat as `DefaultMaxTPDULength` (65531) |
| `1`…`127` | `ErrInvalidConfig` |
| `128`…`65531` | accepted |
| `> 65531` | `ErrInvalidConfig` |

### 5.2 Preferred-maximum encoding (ITOT service flooring)

Service-only (not generic codec):

```text
encodedUnits = floor(configuredMax / 128)   // ≥ 1 when parameter is sent
effectiveMax = encodedUnits * 128
```

| Configured | Units | Effective |
| ---: | ---: | ---: |
| 128 | 1 | 128 |
| 200 | 1 | 128 |
| 1000 | 7 | 896 |
| 1024 | 8 | 1024 |
| 16384 | 128 | 16384 |
| 65531 | 511 | **65408** |

ITOT highest safe preferred units: **511** (`512×128 = 65536` exceeds 65531).

### 5.3 Standard TPDU Size `0xC0` — Class 0 table (X.224 §13.3.4 b)

| Code | Size | Class 0 |
| --- | ---: | --- |
| `0x0D` | 8192 | **not allowed** |
| `0x0C` | 4096 | **not allowed** |
| `0x0B` | 2048 | allowed |
| `0x0A` | 1024 | allowed |
| `0x09` | 512 | allowed |
| `0x08` | 256 | allowed |
| `0x07` | 128 | allowed |

### Fallback algorithm for **our encoder**

```text
fallbackStandard = largest Class-0 standard ≤ preferredEffective
```

| Configured | Preferred effective | `0xC0` fallback |
| ---: | ---: | ---: |
| 128 | 128 | 128 |
| 200 | 128 | 128 |
| 1000 | 896 | 512 |
| 1024 | 1024 | 1024 |
| 16384 | 16384 | 2048 |
| 65531 | 65408 | 2048 |

Decoders must **not** require peer `preferredEffective >= fallbackStandard`.

### 5.4 CR encode by profile

#### `SizeProfileRFC1006Compat`

| Configured | CR encoding |
| --- | --- |
| 0 or 65531 | omit both |
| exact Class-0 standard 128–2048 | `0xC0` only |
| other ≥ 128 | fallback `0xC0` + `0xF0` |

#### `SizeProfilePreferredMaximum`

Always proposes `0xF0`, with `0xC0` as legacy fallback.

| Configured | CR encoding |
| --- | --- |
| exact Class-0 standard 128–2048 | matching `0xC0` **and** matching `0xF0` |
| non-standard ≥ 128 | fallback `0xC0` + `0xF0` |
| 0 / 65531 | `0xC0=2048` + `0xF0=511` → 65408 |

### 5.5 Dual offer: preserve both until path selection

X.224: when preferred maximum is present, the responder either ignores `0xF0` and uses `0xC0`, or honors `0xF0`, ignores `0xC0`, and returns only `0xF0` in CC. The parameters are alternative paths — Standard > Preferred is **valid**.

```go
type sizeOffer struct {
    Standard  *int // when 0xC0 present
    Preferred *int // preferred effective octets when 0xF0 present (ITOT-validated)
    Omitted   bool
}
```

| CR parameters | Internal | `ConnectIndication.MaxTPDULength` |
| --- | --- | --- |
| Neither | Omitted | 65531 (Compat default) |
| `0xC0` only | Standard | standard |
| `0xF0` only | Preferred | preferred |
| Both | **both preserved** | preferred (presentation only) |

Default TP0 path: **honor preferred when present**.

### 5.6 CC interpretation and encoding

| CC parameters | Interpretation |
| --- | --- |
| `0xF0` only | selected preferred |
| `0xC0` only | selected standard |
| Neither | profile-specific |
| Both | malformed on input; our responder never sends both |

**Omitted CC size** (implementation compatibility — COMPLIANCE E-10):

| Local profile | Behavior |
| --- | --- |
| Compat | `negotiated = min(clientEffectiveProposal, 65531)` |
| PreferredMaximum | handshake error |

Never raise above the client’s local effective proposal.

#### Incoming CC path validation (frozen)

A returned selection must be valid for the **exact path offered in our CR**, not merely ≤ some other local ceiling.

| CR we sent | Valid CC size mechanisms |
| --- | --- |
| `0xC0` only | `0xC0` only, or omission under Compat |
| `0xF0` only | `0xF0` only |
| both | either `0xC0` **or** `0xF0` (not both) |
| neither (Compat omit) | omission, or an explicit valid selection under Compat policy |

Path-specific bounds:

| CC selection | Must satisfy |
| --- | --- |
| `0xF0 = u` | preferred was offered; `u×128` ≤ our preferred offer |
| `0xC0 = s` | standard was offered (or Compat omitted-CR path); `s` ≤ our standard fallback/offer |
| Example: CR `0xC0=512` + `0xF0=896` | CC `0xF0=7` (896) OK; CC `0xF0=8` (1024) **reject**; CC `0xC0=512` OK; CC `0xC0=1024` **reject** |

A peer must not select a mechanism that was not offered, except Compat omission of all size parameters on CR (legacy default path).

#### Responder CC when peer CR omits both size parameters (frozen)

Omitted CR under Compat means the peer effectively proposes **65531**. Do **not** respond with `0xF0` to a peer that did not offer preferred maximum.

| Server effective ceiling | Compat CC response to omitted CR |
| --- | --- |
| 65531 | omit size parameters |
| exact Class-0 standard 128–2048 | send that `0xC0` |
| non-standard ceiling | send largest Class-0 `0xC0` ≤ ceiling |

Examples: server 1024 → `0xC0=1024`; server 1000 → `0xC0=512`; server 16384 → `0xC0=2048`; server 65531 → omit.

Under `SizeProfilePreferredMaximum`, a legacy omitted CR is still accepted, but the response remains on the **standard/legacy** path (no manufactured `0xF0`). Profile controls local encoding preference; it cannot invent peer support.

### 5.7 Responder selection (path-normalized ceiling model)

Do **not** take a raw integer `min` and normalize only at encode time — that can record a `NegotiatedParameters.MaxTPDULength` that differs from the wire selection.

Selection is performed in the **selected path’s representable domain**:

```text
// Choose path first (honor preferred when present & we honor it; else standard; else omitted).
if preferred path:
    normalize(ceiling) = floor(ceiling / 128) * 128
if standard path:
    normalize(ceiling) = largest Class-0 0xC0 value ≤ ceiling

selected = min(
    peer path-specific offer,
    normalize(serverCeiling),
    normalize(callbackCeiling),   // when AcceptDecision.MaxTPDULength ≠ 0
)
```

Examples:

| Peer offer | Ceilings | Path | Selected |
| --- | --- | --- | ---: |
| preferred 1024 | server 1024, callback 1000 | preferred | **896** |
| standard 1024 | server 1000 | standard | **512** |
| preferred … | callback 129 | preferred | **128** |
| standard … | callback 129 | standard | **128** |

Higher raw callback ceilings that normalize above the peer offer still have no raising effect. Encode the selected value per §5.6; store that same value in `NegotiatedParameters.MaxTPDULength`.

### 5.8 Server `SizeProfile` meaning

CR parser always accepts valid `0xC0`/`0xF0`. Profile governs CC encode and omission policy — not CR parse rejection. PreferredMaximum does not emit `0xF0` toward a peer that did not offer it (§5.6 omitted-CR table).

### 5.9 Internal pure functions (unexported)

```go
func normalizeConfiguredMax(configured int) (int, error)
func preferredUnitsAndEffective(configured int) (units uint32, effective int, err error) // floors
func fallbackStandard(preferredEffective int) (size int, code uint8, err error)

func buildSizeOffer(configured int, profile SizeProfile) (sizeOffer, error)
func decodeSizeOffer(standard *uint8, preferredUnits *uint32) (sizeOffer, error)
func selectSize(...) (sizeSelection, error)
func interpretCCSize(...) (effective int, err error)
```

ITOT ceilings (`units ≤ 511`, `configured ≤ 65531`) enforced here — **not** in `DecodeCR`/`DecodeCC`.

### 5.10 Preferred-maximum codec (generic X.224)

```go
type CR struct {
    TPDUSize             *uint8
    PreferredMaxTPDUSize *uint32 // wire units; nil = absent
    // ...
}
type CC struct {
    TPDUSize             *uint8
    PreferredMaxTPDUSize *uint32
    // ...
}

const ParamPreferredMaxTPDUSize = 0xF0

// Generic codec helpers — exact conversion, portable on 32-bit:
func PreferredMaxTPDULength(units uint32) (uint64, error) // units×128
func PreferredMaxTPDUUnits(length uint64) (uint32, error)
// length == 0              → error
// length % 128 != 0        → error
// length/128 > MaxUint32   → error
```

Flooring (`configured / 128`) stays in **service** `preferredUnitsAndEffective` only.

| Layer | Rule |
| --- | --- |
| Codec encode | minimal BE length; no leading zeros; units ≥ 1; 1–4 octets |
| Codec decode | accept 1–4 octets **including leading zeros**; reject len 0/>4; reject units == 0; **no** ITOT 511/65531 clamp |
| ITOT service | units ≤ 511; effective ≤ 65408 via `0xF0`; configured ≤ 65531 |

**Codec vectors:** `F0 01 01` → 1; `F0 02 00 01` → 1 accepted; `F0 04 00 00 01 FF` → 511; `F0 00` / `F0 05…` invalid; all-zero invalid; units > 511 accepted by codec.

### 5.11 Exhaustive cases (1–60)

| # | Case | Expected |
| --- | --- | --- |
| 1 | Configured `0` | Compat omit; PreferredMaximum `0xC0=2048`+`0xF0=511` |
| 2 | Configured `<128` | `ErrInvalidConfig` |
| 3 | Exact 128 | Compat `0xC0`; PreferredMaximum `0xC0`+`0xF0=1` |
| 4 | Exact 1024 | Compat `0xC0=0x0A`; PreferredMaximum + `0xF0=8` |
| 5 | Non-standard 1000 | preferred 896, fallback 512 |
| 6 | Non-standard 16384 | preferred 16384, fallback 2048 |
| 7 | Maximum 65531 | Compat omit; PreferredMaximum → 65408 |
| 8 | Configured `>65531` | `ErrInvalidConfig` |
| 9 | Peer neither | omitted; Compat default 65531 (local-capped on CC) |
| 10 | Peer only `0xC0` | standard path |
| 11 | Peer only `0xF0` | preferred path |
| 12 | Both: standard ≤ preferred | valid dual offer |
| 13 | Both: standard > preferred | **valid**; path selects which is used |
| 14 | Invalid preferred length / zero | reject |
| 15 | Peer returns fallback `0xC0` | accept if ≤ offered standard |
| 16 | Peer honors `0xF0` in CC | accept if ≤ offered preferred |
| 17a | Compat CC omission | `min(localEffectiveProposal, 65531)` |
| 17b | PreferredMaximum CC omission | handshake error |
| 18 | Callback ceiling lower | selected lowered (path-normalized) |
| 19 | Callback ceiling higher | accepted; no raise |
| 20 | Leading-zero preferred encoding | codec accepts; encoder normalizes |
| 21 | Units > 511 in generic codec | accepted |
| 22 | Units > 511 in ITOT service | handshake reject |
| 23 | Server selector set, CR selector absent | default reject |
| 24 | CC selector mismatched | client handshake fails |
| 25 | Context expires after first DT | whole Conn aborts |
| 26 | Local `Close` wakes blocked read | `ErrClosed` |
| 27 | `MaxTSDULength < 0` | `ErrInvalidConfig` |
| 28 | `WriteTSDU` larger than max | `ErrTSDUTooLarge`, no I/O, Conn usable |
| 29 | Reassembly exceeds max | abort connection |
| 30 | Server CR `SRC-REF=0` | reject/ER or close |
| 31 | Client CC `SRC-REF=0` | handshake failure |
| 32 | Client mismatched CC `DST-REF` | handshake failure |
| 33 | Class 0 CR non-zero CDT | reject |
| 34 | Class 0 CR non-zero option bits | reject |
| 35 | Class 0 CC non-zero CDT/options | handshake failure |
| 36 | DT illegal Class 0 encoding (`0xF1` / non-zero TPDU-NR) | abort |
| 37 | `OnConnect` returns error | conn closed; callback error preserved + `ErrHandshake` |
| 38 | `OnConnect` invalid action | conn closed; policy/config error |
| 39 | Preferred offer 1024 + callback ceiling 1000 | selected **896** |
| 40 | Standard offer 1024 + server ceiling 1000 | selected **512** |
| 41 | Callback ceiling 129 on preferred path | selected **128** |
| 42 | Callback ceiling 129 on standard path | selected **128** |
| 43 | CR offers F0=896; CC selects F0=1024 | reject |
| 44 | CR fallback C0=512; CC selects C0=1024 | reject |
| 45 | CR sends C0 only; CC sends F0 only | reject |
| 46 | CR sends F0 only; CC sends C0 only | reject |
| 47 | Omitted CR + server 65531 | Compat CC omission |
| 48 | Omitted CR + server 1024 | CC `0xC0=1024` |
| 49 | Omitted CR + server 1000 | CC `0xC0=512` |
| 50 | Omitted CR + PreferredMaximum server | standard/legacy response, **not** F0 |
| 51 | Client `ConnectData` len 32 | accepted if CR total ≤128 |
| 52 | Client `ConnectData` len 33 | `ErrInvalidConfig` before I/O |
| 53 | Server CC `ConnectData` len 33 | policy/handshake error before CC write |
| 54 | CR unknown parameter | ignored for service semantics |
| 55 | CR known Class-0-forbidden parameter | reject |
| 56 | CC unknown parameter | handshake failure |
| 57 | CC known Class-0-forbidden parameter | handshake failure |
| 58 | Allocator wraps while candidate still active | skips candidate |
| 59 | Reference released exactly once on terminal transition | no double-free / leak |
| 60 | Concurrent allocations | never return duplicate active references |

### 5.12 Test organization

Do **not** implement all 60 cases as one monolithic table. Split into focused suites:

| File | Coverage |
| --- | --- |
| `preferred_max_codec_test.go` | generic `0xF0` parsing, encoding, exact conversion |
| `size_offer_test.go` | CR offer construction and decoding |
| `size_selection_test.go` | path-normalized responder selection |
| `size_confirmation_test.go` | CC mechanism and bound validation |
| `handshake_validation_test.go` | selectors, references, Class 0 fields, parameters |
| `reference_allocator_test.go` | wrap, concurrency, release |
| `service_limits_test.go` | TSDU and connect-data policies |

This keeps failures diagnosable and prevents negotiation from collapsing into one opaque function.

---

## 6. Segmentation, Class 0 bit rules, and TSDU bounds

### Maximum DT user data (frozen)

```text
maxUserDataPerDT = NegotiatedMaxTPDULength - 3
```

65528 is max **per DT segment**, not max TSDU. RFC 1006 65524 is a documented discrepancy (COMPLIANCE E-09).

### Symmetric `MaxTSDULength` (frozen)

Limits both `WriteTSDU` and `ReadTSDU`.

| Config | Result |
| --- | --- |
| `< 0` | `ErrInvalidConfig` |
| `0` | default 4 MiB |
| `> 0` | accepted local policy |

Write oversize → `ErrTSDUTooLarge` before I/O (Conn usable).  
Read reassembly oversize → **abort** connection.

### 6.1 Class 0 fixed-field and DT encoding (frozen)

Copied for P1 implementability (X.224 §13.3.3, §13.4.3, §13.7.3; RFC 2126 §6.5).

**Class 0 CR (input and our output):**

| Field | Required |
| --- | --- |
| CDT (octet 2 bits 4–1) | `0000` |
| Preferred class (octet 7 bits 8–5) | `0000` (class 0) |
| Option bits (octet 7 bits 4–1) | `0000` |
| ⇒ `ClassOption` octet | `0x00` |

**Class 0 CC:**

| Field | Required |
| --- | --- |
| CDT | `0000` |
| Selected class | `0000` |
| Class 0 option bits | `0000` |
| ⇒ `ClassOption` | `0x00` |

**Minimal DT (Class 0/1 format; LI = 2; total TPDU length = 3 + user data):**

LI counts the fixed (and variable) header after the LI octet and **excludes** user data. For minimal Class 0 DT the fixed part is octets 2–3, so:

```text
LI = 2
total TPDU length = 1 + LI + userDataLength = 3 + userDataLength
```

Do **not** encode LI as the complete TPDU length.

| Field | Our output | Accepted input |
| --- | --- | --- |
| Type bits 8–5 | `1111` | `1111` |
| Type bits 4–2 | `000` | `000` |
| ROA bit 1 | `0` | **must be 0** (request-ack not used in Class 0) |
| ⇒ type octet | `0xF0` | **`0xF0` only** (`0xF1` illegal in P1 TP0) |
| TPDU-NR (bits 7–1 of octet 3) | `0` | **must be 0** (X.224: zero in class 0) |
| EOT (bit 8 of octet 3) | 0 or 1 | 0 or 1 |

RFC 2126 §6.5: credit and TPDU-NR fields are **not** ignored on input — enforce the Class 0 encoding above rather than accepting arbitrary values.

Violation on CR/CC → handshake reject. Violation on DT after open → abort.

### 6.2 Class 0 parameter whitelist (frozen)

X.224 Class 0 CR/CC may contain only transport selectors, maximum TPDU size, and preferred maximum TPDU size (and no data field). RFC 1006 adds the ITOT connect-data exception.

**CR (TP0 / ITOT engine):**

| Parameter / field | Policy |
| --- | --- |
| Calling / called selectors (`0xC1`/`0xC2`) | allowed |
| TPDU size (`0xC0`) | allowed (Class-0 codes only) |
| Preferred maximum (`0xF0`) | allowed |
| Connect data (user data) | allowed only as ITOT extension; ≤ `MaxConnectDataLength` |
| Unknown parameter | ignore for service semantics (X.224 CR unknown-parameter rule); may retain for diagnostics |
| Known Class-0-forbidden parameter (e.g. checksum, QoS, additional options, …) | **reject** as unacceptable CR |

**CC (TP0 / ITOT engine):**

| Parameter / field | Policy |
| --- | --- |
| Responding / calling selector as applicable | allowed |
| `0xC0` / `0xF0` | allowed per path rules (§5.6) |
| Connect data | ITOT only; ≤ `MaxConnectDataLength` |
| Unknown parameter | **protocol error** (CC is not CR) → handshake failure |
| Known Class-0-forbidden parameter | handshake failure |

Generic codec may still preserve unknown parameters for tooling (COMPLIANCE B-07); the **engine** enforces this whitelist.

### WriteTSDU / ReadTSDU

- Empty → `ErrEmptyTSDU` (local P1 policy).
- Segment with EOT only on final DT; one TPDU per TPKT.
- Reassembly until EOT; bound by `MaxTSDULength`.

---

## 7. Concurrency, I/O-start, and terminal cause

1. Exclusive `net.Conn` ownership after `Connect`/`Accept` entry.
2. One concurrent `ReadTSDU` + one concurrent `WriteTSDU`.
3. `Close` may run concurrently; universal unblock for both directions.

### 7.1 When protocol I/O has “started”

**Conservative definition:** protocol I/O has started once the first underlying `Read`, `Write`, `ReadPacket`, or `WritePacket` call is **attempted** — not only when a positive byte count is observed.

| Situation | Behavior |
| --- | --- |
| `ctx` done while waiting for `readMu`/`writeMu` (no underlying I/O yet) | return `ctx.Err()`; Conn remains usable |
| `ctx` done **before** any protocol I/O for this call | return `ctx.Err()`; Conn remains usable |
| `ctx` expires/cancels **after** first underlying I/O attempt | **abort and close** entire Conn; both directions unusable; `ErrClosed` + `ctx.Err()` |
| Plain network timeout / incomplete TPKT–TPDU–TSDU | normally **abort** (stream may be desynchronized) |

### 7.2 Terminal-cause arbitration

Concurrent terminal events (local `Close`, peer EOF, context cancel, network reset, malformed TPDU, simultaneous read/write failure) must not produce inconsistent classifications.

**Rule: the first terminal transition recorded by the connection wins.**

```go
type terminalCause struct {
    state terminalState // closed | aborted
    err   error         // classified error for waiters
}
// set once via sync.Once / state lock
```

Subsequent and blocked operations return errors classified from that stored cause.

Examples:

| First winner | Blocked ops see |
| --- | --- |
| Local `Close` | `ErrClosed` |
| Peer EOF | `ErrDisconnected` + `io.EOF` |
| Context cancel after I/O | `ErrClosed` + context error |

`Close` unblocks waiters but must **not** overwrite a peer-disconnect cause already recorded.

---

## 8. Errors

```go
var (
    ErrClosed            = errors.New("cotp: connection closed")
    ErrDisconnected      = errors.New("cotp: peer disconnected")
    ErrConnectionRefused = errors.New("cotp: connection refused")
    ErrHandshake         = errors.New("cotp: handshake failed")
    ErrUnexpectedTPDU    = errors.New("cotp: unexpected TPDU")
    ErrIncompleteTSDU    = errors.New("cotp: incomplete TSDU")
    ErrTSDUTooLarge      = errors.New("cotp: TSDU exceeds configured maximum")
    ErrEmptyTSDU         = errors.New("cotp: empty TSDU")
    ErrInvalidConfig     = errors.New("cotp: invalid configuration")
)

type RejectionError struct {
    Reason DisconnectReason
    Info   []byte // defensive copy
}

func (e *RejectionError) Unwrap() error { return ErrConnectionRefused }

type ConnectionPhase uint8

const (
    PhaseHandshake ConnectionPhase = iota
    PhaseDataTransfer
)

type UnexpectedTPDUError struct {
    Type  TPDUType
    Phase ConnectionPhase
}

func (e *UnexpectedTPDUError) Unwrap() error { return ErrUnexpectedTPDU }

type DisconnectError struct {
    Cause error
}

func (e *DisconnectError) Unwrap() []error {
    return []error{ErrDisconnected, e.Cause}
}
```

---

## 9. Examples

### Client

```go
tcpConn, err := net.Dial("tcp", "plc.example:102")
if err != nil {
    return err
}
cotpConn, err := cotp.Connect(ctx, tcpConn, cotp.ClientConfig{
    LocalSelector:  local,
    RemoteSelector: remote,
    MaxTPDULength:  1024,
})
if err != nil {
    return err // tcpConn already closed
}
defer cotpConn.Close()

if err := cotpConn.WriteTSDU(ctx, req); err != nil {
    return err
}
resp, err := cotpConn.ReadTSDU(ctx)
```

### Server with policy

```go
cotpConn, err := cotp.Accept(ctx, tcpConn, cotp.ServerConfig{
    LocalSelector: calledTSAP,
    MaxTPDULength: 2048,
    OnConnect: func(ctx context.Context, ind cotp.ConnectIndication) (cotp.AcceptDecision, error) {
        if !allowed(ind.CallingSelector) {
            return cotp.AcceptDecision{
                Action:       cotp.ConnectReject,
                RejectReason: cotp.ReasonAddressUnknown,
            }, nil
        }
        return cotp.AcceptDecision{
            Action:        cotp.ConnectAccept,
            MaxTPDULength: 2048,
            ConnectData:   replyGreeting,
        }, nil
    },
})
```

### TLS

```go
tlsConn := tls.Client(raw, tlsConfig)
if err := tlsConn.HandshakeContext(ctx); err != nil { /* ... */ }
cotpConn, err := cotp.Connect(ctx, tlsConn, cfg)
```

---

## 10. go-s7comm migration

```go
local, _ := wire.BuildTSAP(1, 0, 0)
remote, _ := wire.BuildTSAP(3, rack, slot)
sel := func(tsap uint16) []byte {
    b := make([]byte, 2)
    binary.BigEndian.PutUint16(b, tsap)
    return b
}
cotpConn, err := cotp.Connect(ctx, tcpConn, cotp.ClientConfig{
    LocalSelector:  sel(local),
    RemoteSelector: sel(remote),
    MaxTPDULength:  1024,
})
```

Remove production `go-tpkt` and manual CR/DT. Real PLC must verify non-zero SRC-REF (client). Default engine also rejects zero peer references on Accept/Connect (§3.1).

---

## 11. go-mms migration

```go
cotpConn, err := cotp.Connect(ctx, tlsOrTCP, cotp.ClientConfig{
    LocalSelector:  opts.CallingTSelector,
    RemoteSelector: opts.CalledTSelector,
    SizeProfile:    cotp.SizeProfileRFC1006Compat,
})
```

Server: `Accept` + optional `OnConnect`. Delete `transport/iso` framing.

---

## 12. P1 non-goals

1. Class 1–4 / TP2 / AK/RJ / established DR–DC release.
2. Expedited data / ED-as-DT experiments.
3. Public TPKT configuration.
4. Silent discard of ITOT connect data / claiming it is generic X.224 Class 0.
5. Empty TSDU as normative (local reject only).
6. Using RFC 1006’s 65524 figure for DT segmentation.
7. Relocating codecs to `cotp/tpdu`.
8. Treating reported RFC 2126 size erratum as verified normative text.
9. Silent clamp of `MaxTPDULength` outside `[128, 65531]` (except `0` → default).
10. Rejecting peer dual offers when Standard > Preferred.
11. Enforcing ITOT 511-unit ceiling or flooring inside the generic `0xF0` codec.
12. Silently accepting zero peer SRC-REF.
13. Accepting DT type `0xF1` (ROA) in Class 0 TP0.
14. Encoding minimal-DT LI as total TPDU length (LI excludes user data; LI=2).
15. Raw integer size mins without path-domain normalization.
16. Responding with `0xF0` to a peer that did not offer preferred maximum.
17. Overloading `SizeProfile` to reject valid legacy CR decode.
18. Exporting full internal state-machine vocabulary on public errors.
19. Promising nil-receiver `Close` safety.
20. Returning `ErrDisconnected` for local `Close()`.
21. `AllowZeroPeerReference` until a consumer demonstrates need.
22. Process-wide ref counter without tracking active references.

---

## 13. Freeze checklist

| Item | Status |
| --- | --- |
| Architecture | **frozen** |
| Public API surface | **provisionally frozen** |
| Negotiation / handshake rules | **fully specified** |
| DR reason constants + default refusal mappings | **specified** (`ReasonNotSpecified` = 0) |
| Symmetric `MaxTSDULength` / `MaxConnectDataLength=32` | **specified** |
| Collision-safe reference allocator | **specified** |
| Class 0 bits + parameter whitelist | **specified** |
| Path-normalized selection + CC path validation | **specified** |
| Omitted-CR responder CC table | **specified** |
| Minimal DT LI = 2 (not 2+user data) | **specified** |
| Exact `0xF0` helpers (`uint64` / exact units) | **done** |
| Typed `0xF0` codec implementation | **done** |
| Cases 1–60 tests (§5.12 suites) | **done / green** |
| Consumer migration evidence (§13.1) | **TODO** (after engine) |

### 13.1 Consumer evidence (executable gates)

- [ ] go-s7comm migration spike compiles and passes tests against local go-cotp
- [ ] go-mms client migration spike compiles and passes tests
- [ ] go-mms server `Accept` path compiles and passes tests
- [ ] no production go-tpkt imports remain in either consumer
- [ ] real S7 PLC verifies non-zero source reference

---

## 14. Implementation order

### Completed: negotiation prerequisite

Typed `0xF0` codec, exact helpers, pure size-negotiation / handshake validators, reference allocator, and cases 1–60 (§5.12) are implemented and green.

### In progress: TP0 engine

1. ~~Config / connect-data preflight, ownership, wire up reference allocator, terminal-cause once, internal TPKT.~~
2. ~~Client handshake (refs, Class 0 bits/whitelist, CC path validation, connect data ≤32).~~
3. ~~Server handshake (`ConnectIndication`, selector policy, omitted-CR CC table, callback contracts, CC/DR/ER).~~
4. ~~Single-DT TSDU transfer + concurrency (§7); LI=2 encoding.~~
5. ~~Segmentation / reassembly + symmetric TSDU bound.~~
6. ~~Open-state unexpected TPDU / framing abort coverage (§3 / §6).~~
7. Consumer migration spikes (§13.1).

---

## 15. Compliance notes

Record in [COMPLIANCE.md](COMPLIANCE.md):

> **E-09:** RFC 1006 65524 vs X.224 TPDU−3 — use X.224 for segmentation.  
> **E-10:** Compat omitted-CC local-cap is an implementation / installed-base choice.  
> **B-07 / §6.2:** Codec may preserve unknown params; TP0 engine enforces Class 0 whitelist and protocol error outside CR.  
> **B-10 / B-21:** Non-zero refs + collision-safe active-reference allocator.  
> **B-14 / B-22:** Generic `0xF0` wire range vs ITOT 511-unit service ceiling.  
> **Connect data:** ITOT extension with service ceiling `MaxConnectDataLength = 32`.
