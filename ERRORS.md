# Error Reference

go-cotp uses Go's standard error model with sentinel values and typed structs.
Use `errors.Is` for category checks; use `errors.As` to extract structured detail.

---

## Decode / encode sentinels

These are returned by `Decode`, `DecodeCR`, `DecodeCC`, `DecodeDT`, and
similar codec functions. All are defined in `errors.go` and can be imported as
`cotp.ErrXxx`.

| Sentinel | When returned |
|----------|---------------|
| `ErrTooShort` | Input buffer is shorter than required for the TPDU fixed part |
| `ErrInvalidLI` | Length indicator is invalid (> 254, or shorter than the fixed part) |
| `ErrLengthMismatch` | TPDU length constraint violated (e.g. CR > 128 octets) |
| `ErrUnknownTPDUType` | TPDU type code is not defined by X.224 |
| `ErrInvalidTPDUCode` | TPDU type code is reserved or invalid |
| `ErrReservedTPDU` | TPDU type code is explicitly reserved |
| `ErrMalformedParameter` | Variable-part parameter TLV is malformed (e.g. length overrun) |
| `ErrUnexpectedParameterLength` | Parameter length is outside the allowed range for that type |
| `ErrUnsupportedTPDU` | TPDU is structurally valid but not decoded by this implementation |
| `ErrUnsupportedDTVariant` | DT extended-format variant is not supported |
| `ErrInvalidClassOption` | Class/option field is invalid |
| `ErrDuplicateKnownParameter` | Retained for compatibility; no longer returned (last-wins per X.224 13.2.3) |
| `ErrInvalidEDUserDataLength` | ED user data length is outside 1–16 octets |
| `ErrNilReceiver` | `MarshalBinary` called on nil `*CR` / `*CC` / etc. |
| `ErrMissingRequiredField` | Required encode field is missing or invalid |
| `ErrInvalidConfig` | TP0/ITOT service configuration is invalid |
| `ErrHandshake` | TP0 CR/CC handshake or open-state protocol validation failed |

---

## Connection sentinels

These are returned by `Connect`, `Accept`, `ReadTSDU`, and `WriteTSDU`.

| Sentinel | When returned |
|----------|---------------|
| `ErrEmptyTSDU` | Zero-length TSDU was rejected (local policy) |
| `ErrTSDUTooLarge` | TSDU exceeds `MaxTSDULength` |
| `ErrClosed` | Local `Close` was called; this side initiated the teardown |
| `ErrDisconnected` | Peer disconnected (EOF / TCP reset); not a local Close |
| `ErrConnectionRefused` | Peer sent a DR during the handshake |
| `ErrUnexpectedTPDU` | Received a TPDU that is not legal in the current phase |
| `ErrIncompleteTSDU` | EOF or connection abort while reassembling a multi-DT TSDU |

---

## Typed errors

Use `errors.As` to extract structured detail.

### `*RejectionError`

Returned by `Connect` or `Accept` when the peer actively refuses the
connection by sending a DR TPDU during the handshake.

```go
type RejectionError struct {
    Phase  ConnectionPhase // Handshake or OpenState
    Reason DisconnectReason
    Info   string
}
```

Wraps `ErrConnectionRefused`.

### `*UnexpectedTPDUError`

Returned by `ReadTSDU` or `WriteTSDU` when a TPDU is received that is not
valid for the current connection phase.

```go
type UnexpectedTPDUError struct {
    Phase    ConnectionPhase
    TPDUType TPDUType
    Msg      string
}
```

Wraps `ErrUnexpectedTPDU`.

### `*DisconnectError`

Returned by `ReadTSDU` when the peer sends a DR or DC TPDU signalling an
intentional disconnect.

```go
type DisconnectError struct {
    Phase  ConnectionPhase
    Reason DisconnectReason
    Info   string
}
```

Wraps `ErrDisconnected`.

---

## `ConnectionPhase` constants

```go
const (
    PhaseHandshake ConnectionPhase = iota
    PhaseOpenState
)
```

---

## Usage patterns

```go
import (
    "errors"
    "github.com/otfabric/go-cotp"
)

// Service API
conn, err := cotp.Connect(ctx, tcpConn, cfg)
if err != nil {
    switch {
    case errors.Is(err, cotp.ErrConnectionRefused):
        // peer sent DR
        var re *cotp.RejectionError
        if errors.As(err, &re) {
            log.Printf("refused: reason=%v", re.Reason)
        }
    case errors.Is(err, cotp.ErrHandshake):
        // handshake protocol error
    default:
        return err
    }
}

_, err = conn.ReadTSDU(ctx)
if err != nil {
    switch {
    case errors.Is(err, cotp.ErrClosed):
        // local Close was called
    case errors.Is(err, cotp.ErrDisconnected):
        // peer went away
        var de *cotp.DisconnectError
        if errors.As(err, &de) {
            log.Printf("disconnect reason=%v", de.Reason)
        }
    }
}
```

```go
// Codec API
decoded, err := cotp.Decode(tpduBytes)
if err != nil {
    switch {
    case errors.Is(err, cotp.ErrTooShort):
        // reassembly or framing issue upstream
    case errors.Is(err, cotp.ErrUnknownTPDUType):
        // unknown TPDU type on the wire
    }
}
```
