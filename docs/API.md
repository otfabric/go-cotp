# go-cotp API reference

Public API of package `github.com/otfabric/go-cotp` (package name: `cotp`).

**Two surfaces:**

1. **TP0 transport service** — `Connect` / `Accept` / `ReadTSDU` / `WriteTSDU` / `Close` (preferred for applications).
2. **TPDU codec** — `Decode` / `MarshalBinary` on one complete COTP TPDU payload (no TPKT header; typically from [go-tpkt](https://github.com/otfabric/go-tpkt) v1).

Multi-octet fields use network byte order (big-endian). Architecture: [ARCHITECTURE.md](ARCHITECTURE.md). Compliance: [COMPLIANCE.md](COMPLIANCE.md). Frozen service contract: [TP0_API_DESIGN.md](TP0_API_DESIGN.md).

---

## TP0 service

```go
func Connect(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Conn, error)
func Accept(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Conn, error)
func (c *Conn) ReadTSDU(ctx context.Context) ([]byte, error)
func (c *Conn) WriteTSDU(ctx context.Context, tsdu []byte) error
func (c *Conn) Close() error
func (c *Conn) Negotiated() NegotiatedParameters
func (c *Conn) LocalAddr() net.Addr
func (c *Conn) RemoteAddr() net.Addr
```

### Ownership and concurrency

- `Connect` / `Accept` take ownership of `conn` **immediately**, including on config or handshake failure (conn is closed).
- TPKT framing is internal; `*Conn` callers must not wrap the same stream with go-tpkt.
- One reader + one writer may run concurrently; additional concurrent readers/writers are unsupported.
- `Close` returns `ErrClosed` when it wins the terminal cause; otherwise it returns the first terminal cause. It unblocks waiters by closing the underlying stream.
- Context expiry **after** I/O has started aborts the whole connection (`ErrClosed` + context error).
- Empty TSDUs are rejected (`ErrEmptyTSDU`). Reassembly is bounded by `MaxTSDULength`.

### Config highlights

| Type | Notes |
|------|--------|
| `ClientConfig` | Selectors, `MaxTPDULength` / `MaxTSDULength`, `ConnectData` (≤32), `SizeProfile` |
| `ServerConfig` | `LocalSelector` nil vs empty semantics; optional `OnConnect` policy |
| `SizeProfileRFC1006Compat` | Default; standard `0xC0` path |
| `SizeProfilePreferredMaximum` | Dual-offer / `0xF0` preferred-max path |
| `NegotiatedParameters` | Frozen after handshake; slices are defensive copies; nil selector = absent |

`ReadTSDU` / `WriteTSDU` use minimal Class 0 DT segmentation (`LI=2`, `TPDU-NR=0`, `EOT` only on the final segment; max user data per DT = negotiated TPDU length − 3).

Typed errors: `RejectionError`, `UnexpectedTPDUError`, `DisconnectError` — use `errors.Is` / `errors.As`.

### Pre-v1 API review notes (2026-07-16)

Reviewed via `go doc -all github.com/otfabric/go-cotp` against [TP0_API_DESIGN.md](TP0_API_DESIGN.md):

| Check | Result |
|-------|--------|
| Naming | Consistent (`Connect`/`Accept`, `ReadTSDU`/`WriteTSDU`, `MaxTPDULength`) |
| Zero values | `MaxTPDULength`/`MaxTSDULength` 0 → documented defaults; `SizeProfile` 0 → RFC1006Compat |
| nil vs empty slices | Selectors: nil=absent, non-nil empty=present len 0 (documented on `ServerConfig` / `NegotiatedParameters`) |
| Ownership | Immediate ownership documented on `Connect`/`Accept` and in package doc |
| Error wrapping | Sentinels + typed errors; `errors.Is`/`As` supported |
| Internal leakage | `referenceAllocator`, size-path enums, ER cause constants remain unexported |
| Codec vs service | Separated in package doc / README; codec still fully exported for tooling |
| Godoc gaps | Minor: some codec `LooksLike*` helpers are terse; service types are adequate |

No public API renames required before RC.

---

## Decode (codec)

### Decode

```go
func Decode(b []byte) (Decoded, error)
```

Parses a complete COTP TPDU from `b` and returns a `Decoded` struct. On success, exactly one of `CR`, `CC`, `DT`, `DR`, `DC`, `ER`, `ED`, `AK`, `EA`, `RJ` is non-nil and `Type` matches it. On error, the returned `Decoded` is the zero value; it is never partially filled.

### DecodeWithRaw

```go
func DecodeWithRaw(b []byte) (Decoded, error)
```

Like `Decode` but on success sets `Decoded.Raw` to the exact input slice `b`. `Raw` may alias `b`; callers must copy if retaining or mutating beyond the lifetime of `b`. On error, returns zero `Decoded` (Raw is unavailable by design).

### Per-TPDU decode

| Function | Returns | Description |
|----------|---------|-------------|
| `DecodeCR(b []byte) (*CR, error)` | `*CR` | Connection Request |
| `DecodeCC(b []byte) (*CC, error)` | `*CC` | Connection Confirm |
| `DecodeDT(b []byte) (*DT, error)` | `*DT` | Data |
| `DecodeDR(b []byte) (*DR, error)` | `*DR` | Disconnect Request |
| `DecodeDC(b []byte) (*DC, error)` | `*DC` | Disconnect Confirm |
| `DecodeER(b []byte) (*ER, error)` | `*ER` | TPDU Error |
| `DecodeED(b []byte) (*ED, error)` | `*ED` | Expedited Data |
| `DecodeAK(b []byte) (*AK, error)` | `*AK` | Acknowledge |
| `DecodeEA(b []byte) (*EA, error)` | `*EA` | Expedited Acknowledge |
| `DecodeRJ(b []byte) (*RJ, error)` | `*RJ` | Reject |

---

## Encode

Each TPDU type has a `MarshalBinary` method implementing `encoding.BinaryMarshaler`:

| Method | Description |
|--------|-------------|
| `(*CR).MarshalBinary() ([]byte, error)` | Encode Connection Request (canonical param order 0xC1, 0xC2, 0xC0, 0xF0, then UserData; max 128 octets). |
| `(*CC).MarshalBinary() ([]byte, error)` | Encode Connection Confirm (same param order and UserData rules as CR). |
| `(*DT).MarshalBinary() ([]byte, error)` | Encode Data (minimal or normal format). |
| `(*DR).MarshalBinary() ([]byte, error)` | Encode Disconnect Request. |
| `(*DC).MarshalBinary() ([]byte, error)` | Encode Disconnect Confirm. |
| `(*ER).MarshalBinary() ([]byte, error)` | Encode TPDU Error. |
| `(*ED).MarshalBinary() ([]byte, error)` | Encode Expedited Data (user data 1–16 octets). |
| `(*AK).MarshalBinary() ([]byte, error)` | Encode Acknowledge. |
| `(*EA).MarshalBinary() ([]byte, error)` | Encode Expedited Acknowledge. |
| `(*RJ).MarshalBinary() ([]byte, error)` | Encode Reject. |

Calling `MarshalBinary` on a nil receiver returns an error wrapping `ErrNilReceiver`. Use `errors.Is(err, cotp.ErrNilReceiver)` to detect.

---

## Wire and helpers

| Function | Signature | Description |
|----------|-----------|-------------|
| `ReadLI` | `ReadLI(b []byte) (uint8, error)` | Length indicator from first octet. Valid 0–254. |
| `HeaderLength` | `HeaderLength(b []byte) (int, error)` | Total header length: 1 (LI) + LI value; header = `b[0:HeaderLength(b)]`. |
| `PeekType` | `PeekType(b []byte) (TPDUType, error)` | TPDU type from first two octets; minimal validation only. |
| `ExtractUserData` | `ExtractUserData(b []byte) ([]byte, error)` | User data of a DT or ED TPDU. Returns error if not DT/ED. Returned slice may alias `b`. |
| `PreferredMaxTPDULength` | `PreferredMaxTPDULength(units uint32) (uint64, error)` | Exact `units×128` (generic codec; no ITOT clamp; units≠0). |
| `PreferredMaxTPDUUnits` | `PreferredMaxTPDUUnits(length uint64) (uint32, error)` | Exact units for a multiple of 128 (no flooring). |

---

## Detection (classification only)

Lightweight helpers for protocol classification. They do not fully decode; they check LI, buffer length, and type code only.

| Function | Signature | Description |
|----------|-----------|-------------|
| `LooksLikeCR` | `LooksLikeCR(b []byte) bool` | True if valid LI, enough length, type 0xE0..0xEF. |
| `LooksLikeCC` | `LooksLikeCC(b []byte) bool` | True if valid LI, enough length, type 0xD0..0xDF. |
| `LooksLikeDT` | `LooksLikeDT(b []byte) bool` | True if valid LI, enough length, type 0xF0..0xF1 (same mask as `PeekType`). |
| `LooksLikeDR` | `LooksLikeDR(b []byte) bool` | True if valid LI, enough length, type 0x80. |
| `LooksLikeDC` | `LooksLikeDC(b []byte) bool` | True if valid LI, enough length, type 0xC0. |
| `LooksLikeER` | `LooksLikeER(b []byte) bool` | True if valid LI, enough length, type 0x70. |
| `LooksLikeED` | `LooksLikeED(b []byte) bool` | True if valid LI, enough length, type 0x10. |
| `LooksLikeAK` | `LooksLikeAK(b []byte) bool` | True if valid LI, enough length, type 0x60..0x6F. |
| `LooksLikeEA` | `LooksLikeEA(b []byte) bool` | True if valid LI, enough length, type 0x20. |
| `LooksLikeRJ` | `LooksLikeRJ(b []byte) bool` | True if valid LI, enough length, type 0x50..0x5F. |
| `IsConnectionOriented` | `IsConnectionOriented(b []byte) bool` | True if PeekType is CR, CC, DR, or DC. |
| `IsAckType` | `IsAckType(t TPDUType) bool` | True if `t` is AK or RJ (use after decode). |

---

## Types and structs

### TPDUType

```go
type TPDUType uint8
```

X.224 TPDU type code. Low bits carry CDT/options for some types.

**Constants:** `TypeCR`, `TypeCC`, `TypeDR`, `TypeDC`, `TypeDT`, `TypeER`, `TypeED`, `TypeAK`, `TypeEA`, `TypeRJ`.

**Method:** `(TPDUType).String() string` — type name for logging (e.g. `"CR"`, `"DT"`).

---

### Parameter

```go
type Parameter struct {
    Code  uint8
    Value []byte
}
```

Single variable-part parameter. `Value` may alias decode input.

---

### CR (Connection Request)

```go
type CR struct {
    CDT                  uint8
    DestinationRef       uint16
    SourceRef            uint16
    ClassOption          uint8
    Parameters           []Parameter
    CallingSelector      []byte   // from param 0xC1
    CalledSelector       []byte   // from param 0xC2
    TPDUSize             *uint8   // from param 0xC0
    PreferredMaxTPDUSize *uint32  // from param 0xF0; wire units (×128), nil = absent
    UserData             []byte   // octets after header; may alias decode input
}
```

Nil selector = absent; non-nil empty slice = present with length 0. `TPDUSize` / `PreferredMaxTPDUSize` nil = parameter absent. `UserData` is preserved on decode/encode. Total CR length must be ≤ `MaxCRTPDULength` (128). Selector and unknown parameter values longer than `MaxParameterValueLength` (255) are rejected on encode.

Duplicate known parameters (0xC1/0xC2/0xC0/0xF0) follow X.224 13.2.3: **last value wins**. Canonical encode order (0xC1, 0xC2, 0xC0, 0xF0) is a local deterministic choice.

Preferred maximum (`0xF0`) decode accepts 1–4 value octets (including leading zeros); encode uses the minimal big-endian form. The generic codec does **not** enforce the ITOT 511-unit ceiling.

---

### CC (Connection Confirm)

```go
type CC struct {
    CDT                  uint8
    DestinationRef       uint16
    SourceRef            uint16
    ClassOption          uint8
    Parameters           []Parameter
    CallingSelector      []byte
    CalledSelector       []byte
    TPDUSize             *uint8
    PreferredMaxTPDUSize *uint32
    UserData             []byte
}
```

Same nil/empty and user-data semantics as CR (no 128-octet total-length cap on CC), including `PreferredMaxTPDUSize`.

---

### DT (Data)

```go
type DT struct {
    EOT            bool
    TPDUNR         *uint8
    DestinationRef *uint16
    Parameters     []Parameter
    UserData       []byte
}
```

Nil `UserData` or zero-length = valid empty payload. Nil `DestinationRef`/`TPDUNR` = absent (e.g. minimal format). `UserData` may alias decode input.

---

### Decoded

```go
type Decoded struct {
    Type TPDUType
    CR   *CR
    CC   *CC
    DT   *DT
    DR   *DR
    DC   *DC
    ER   *ER
    ED   *ED
    AK   *AK
    EA   *EA
    RJ   *RJ
    Raw  []byte   // set only by DecodeWithRaw; may alias input
}
```

Result of `Decode` or `DecodeWithRaw`. Exactly one of the TPDU pointers is non-nil; `Type` matches it. Zero value is not a valid decoded result. `Raw` is nil when using `Decode` or on error.

---

### DR (Disconnect Request)

```go
type DR struct {
    DestinationRef uint16
    SourceRef      uint16
    Reason         uint8
    Parameters     []Parameter
    UserData       []byte
}
```

`UserData` may alias decode input.

---

### DC (Disconnect Confirm)

```go
type DC struct {
    DestinationRef uint16
    SourceRef      uint16
    Parameters     []Parameter
}
```

---

### ER (TPDU Error)

```go
type ER struct {
    DestinationRef uint16
    RejectCause    uint8
    Parameters     []Parameter
}
```

---

### ED (Expedited Data)

```go
type ED struct {
    DestinationRef *uint16
    TPDUNR         *uint8
    EOT            bool
    Parameters     []Parameter
    UserData       []byte   // 1–16 octets per X.224
}
```

---

### AK (Acknowledge)

```go
type AK struct {
    CDT            uint8    // octet2 & 0x0F
    DestinationRef uint16
    YRTUNR         uint8
    Parameters     []Parameter
}
```

---

### EA (Expedited Acknowledge)

```go
type EA struct {
    DestinationRef uint16
    YREDTUNR       uint8
    Parameters     []Parameter
}
```

---

### RJ (Reject)

```go
type RJ struct {
    CDT            uint8
    DestinationRef uint16
    YRTUNR         uint8
}
```

No variable part per X.224.

---

## Constants

| Name | Value | Description |
|------|--------|-------------|
| `MinHeaderLength` | 2 | Minimum TPDU header size (LI + type code). |
| `MaxLI` | 254 | Maximum length indicator; 255 reserved. |
| `MaxCRTPDULength` | 128 | Maximum CR-TPDU length including LI (X.224 13.3). |
| `MaxParameterValueLength` | 255 | Maximum parameter value length (one-octet length field). |
| `ParamCallingSelector` | 0xC1 | CR/CC parameter: calling transport selector. |
| `ParamCalledSelector` | 0xC2 | CR/CC parameter: called transport selector. |
| `ParamTPDUSize` | 0xC0 | CR/CC parameter: TPDU size. |
| `ParamPreferredMaxTPDUSize` | 0xF0 | CR/CC parameter: preferred maximum TPDU size (units of 128). |
| `MinEDUserDataLen` | 1 | Minimum ED user data length (X.224). |
| `MaxEDUserDataLen` | 16 | Maximum ED user data length (X.224). |

---

## Errors

Sentinel errors for classification with `errors.Is`. Decode/encode functions wrap them with context (e.g. `"decode CR: %w"`). All 10 standard TPDU types (CR, CC, DT, DR, DC, ER, ED, AK, EA, RJ) are supported; `ErrUnsupportedTPDU` is used for reserved or unknown type codes only.

| Variable | Description |
|----------|-------------|
| `ErrTooShort` | Buffer shorter than required (e.g. no LI or type code). |
| `ErrInvalidLI` | Length indicator invalid (> 254, or shorter than the TPDU fixed part). |
| `ErrLengthMismatch` | TPDU length constraint violated (e.g. CR exceeds 128 octets). |
| `ErrUnknownTPDUType` | TPDU type code not recognized (currently unused). |
| `ErrInvalidTPDUCode` | Reserved or invalid TPDU code. |
| `ErrReservedTPDU` | Reserved TPDU type code. |
| `ErrMalformedParameter` | Parameter block malformed (e.g. length overrun). |
| `ErrUnexpectedParameterLength` | Parameter/selector length outside allowed range. |
| `ErrUnsupportedTPDU` | Structurally valid but unsupported type (reserved/unknown). |
| `ErrUnsupportedDTVariant` | Valid DT shape (e.g. extended format) not supported. |
| `ErrInvalidClassOption` | Invalid class/option field (currently unused). |
| `ErrDuplicateKnownParameter` | Retained for compatibility; decode no longer returns it (last-wins). |
| `ErrInvalidEDUserDataLength` | ED user data not 1–16 octets. |
| `ErrNilReceiver` | Method called on nil receiver (e.g. `MarshalBinary` on nil `*CR`). |
| `ErrMissingRequiredField` | Required field for encode missing or invalid. |
| `ErrInvalidConfig` | Invalid TP0/ITOT service configuration or callback policy input. |
| `ErrHandshake` | TP0 handshake validation failure. |
| `ErrEmptyTSDU` | Zero-length TSDU rejected (P1 local policy). |
| `ErrTSDUTooLarge` | TSDU exceeds configured `MaxTSDULength`. |

Example:

```go
if _, err := cotp.Decode(payload); err != nil {
    if errors.Is(err, cotp.ErrTooShort) {
        // buffer too short
    }
    if errors.Is(err, cotp.ErrUnsupportedTPDU) {
        // valid but unsupported type
    }
}
```
