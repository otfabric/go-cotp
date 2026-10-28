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
| `ErrClosed` | Local `Close` was called, or the connection was aborted after I/O (e.g. a context that ended an operation after octets had moved, joined with `context.DeadlineExceeded` / `context.Canceled`) |
| `ErrDisconnected` | The stream went away: peer EOF, TCP reset, broken pipe, or EOF inside a packet; not a local Close |
| `ErrConnectionRefused` | Peer sent a DR during the handshake |
| `ErrUnexpectedTPDU` | Received a TPDU that is not legal in the current phase |
| `ErrIncompleteTSDU` | EOF or connection abort while reassembling a multi-DT TSDU |

A context that ends `ReadTSDU` / `WriteTSDU` **before any octet** of the TSDU
crossed the stream (an idle read, a stalled first write, or waiting for another
caller's TSDU to finish) returns the bare `ctx.Err()`, not wrapped in
`ErrClosed`, and the connection stays usable. The context of one direction
never affects the other direction.

---

## Typed errors

Use `errors.As` to extract structured detail.

### `*RejectionError`

Returned by `Connect` when the peer refuses the connection with a DR TPDU
during the handshake, and by `Accept` when the local policy (or a non-Class-0
CR) refuses it.

```go
type RejectionError struct {
    Reason DisconnectReason
    Info   []byte
}
```

Wraps `ErrConnectionRefused`.

### `*UnexpectedTPDUError`

Returned when a TPDU arrives that is not legal for the current phase (for
example a non-CC reply to CR, or a non-DT TPDU after the connection opened).

```go
type UnexpectedTPDUError struct {
    Type  TPDUType
    Phase ConnectionPhase
}
```

Wraps `ErrUnexpectedTPDU`.

### `*DisconnectError`

Returned by `Connect`, `Accept`, `ReadTSDU`, and `WriteTSDU` when the stream
goes away: peer EOF, TCP reset, broken pipe, or EOF inside a packet. `Cause` is
the underlying error (e.g. `io.EOF`).

```go
type DisconnectError struct {
    Cause error
}
```

Unwraps to both `ErrDisconnected` and `Cause`. Mid-TSDU it is joined with
`ErrIncompleteTSDU`.

---

## `ConnectionPhase` constants

```go
const (
    PhaseHandshake ConnectionPhase = iota
    PhaseDataTransfer
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
    case errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, cotp.ErrClosed):
        // nothing was read; the connection is still open — retry or move on
    case errors.Is(err, cotp.ErrClosed):
        // local Close, or aborted after I/O
    case errors.Is(err, cotp.ErrDisconnected):
        // peer went away
        var de *cotp.DisconnectError
        if errors.As(err, &de) {
            log.Printf("disconnect cause=%v", de.Cause)
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
