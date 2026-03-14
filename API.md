# go-cotp API reference

Public API of package `github.com/otfabric/go-cotp` (package name: `cotp`). Input to decode is one complete COTP TPDU payload (typically from a TPKT frame). Multi-octet fields use network byte order (big-endian).

---

## Decode

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
| `(*CR).MarshalBinary() ([]byte, error)` | Encode Connection Request (canonical param order 0xC1, 0xC2, 0xC0). |
| `(*CC).MarshalBinary() ([]byte, error)` | Encode Connection Confirm. |
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

---

## Detection (classification only)

Lightweight helpers for protocol classification. They do not fully decode; they check LI, buffer length, and type code only.

| Function | Signature | Description |
|----------|-----------|-------------|
| `LooksLikeCR` | `LooksLikeCR(b []byte) bool` | True if valid LI, enough length, type 0xE0..0xEF. |
| `LooksLikeCC` | `LooksLikeCC(b []byte) bool` | True if valid LI, enough length, type 0xD0..0xDF. |
| `LooksLikeDT` | `LooksLikeDT(b []byte) bool` | True if valid LI, enough length, type 0xF0..0xFF. |
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
    CDT             uint8
    DestinationRef  uint16
    SourceRef       uint16
    ClassOption     uint8
    Parameters      []Parameter
    CallingSelector []byte   // from param 0xC1
    CalledSelector  []byte   // from param 0xC2
    TPDUSize        *uint8   // from param 0xC0
}
```

Nil selector = absent; non-nil empty slice = present with length 0. `TPDUSize == nil` = parameter absent.

---

### CC (Connection Confirm)

```go
type CC struct {
    CDT             uint8
    DestinationRef  uint16
    SourceRef       uint16
    ClassOption     uint8
    Parameters      []Parameter
    CallingSelector []byte
    CalledSelector  []byte
    TPDUSize        *uint8
}
```

Same nil/empty semantics as CR.

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
    RejectCause   uint8
    Parameters    []Parameter
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
| `ParamCallingSelector` | 0xC1 | CR/CC parameter: calling transport selector. |
| `ParamCalledSelector` | 0xC2 | CR/CC parameter: called transport selector. |
| `ParamTPDUSize` | 0xC0 | CR/CC parameter: TPDU size. |
| `MinEDUserDataLen` | 1 | Minimum ED user data length (X.224). |
| `MaxEDUserDataLen` | 16 | Maximum ED user data length (X.224). |

---

## Errors

Sentinel errors for classification with `errors.Is`. Decode/encode functions wrap them with context (e.g. `"decode CR: %w"`).

| Variable | Description |
|----------|-------------|
| `ErrTooShort` | Buffer shorter than required (e.g. no LI or type code). |
| `ErrInvalidLI` | Length indicator invalid (> 254 or inconsistent). |
| `ErrLengthMismatch` | Declared length does not match buffer. |
| `ErrUnknownTPDUType` | TPDU type code not recognized. |
| `ErrInvalidTPDUCode` | Reserved or invalid TPDU code. |
| `ErrReservedTPDU` | Reserved TPDU type code. |
| `ErrMalformedParameter` | Parameter block malformed (e.g. length overrun). |
| `ErrUnexpectedParameterLength` | Parameter length outside allowed range. |
| `ErrUnsupportedTPDU` | Structurally valid but unsupported type (reserved/unknown). |
| `ErrUnsupportedDTVariant` | Valid DT shape (e.g. extended format) not supported. |
| `ErrInvalidClassOption` | Invalid class/option field. |
| `ErrDuplicateKnownParameter` | Known parameter code repeated (CR/CC). |
| `ErrInvalidEDUserDataLength` | ED user data not 1–16 octets. |
| `ErrNilReceiver` | Method called on nil receiver (e.g. `MarshalBinary` on nil `*CR`). |
| `ErrMissingRequiredField` | Required field for encode missing or invalid. |

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
