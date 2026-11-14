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
| `ErrLengthMismatch` | TPDU length constraint violated: a CR above 128 octets, or octets after the header of a DC, ER, AK, EA or RJ, which have no data field (X.224 §13.6.1, §13.9.1, §13.10.1, §13.11.1, §13.12.1) |
| `ErrUnknownTPDUType` | Not returned by this version; retained for compatibility. A type code that X.224 does not define is reported as `ErrInvalidTPDUCode` or `ErrReservedTPDU` |
| `ErrInvalidTPDUCode` | TPDU type code is not defined by X.224, or is not the code of the TPDU a typed decoder expects |
| `ErrReservedTPDU` | TPDU type code is explicitly reserved |
| `ErrMalformedParameter` | Variable-part parameter TLV is malformed (e.g. length overrun) |
| `ErrUnexpectedParameterLength` | Parameter length is outside the allowed range for that type |
| `ErrUnsupportedTPDU` | TPDU is structurally valid but not decoded by this implementation |
| `ErrUnsupportedDTVariant` | DT whose LI is neither 2 (class 0 and 1 format) nor an even value of 4 or more (normal class 2 to 4 format): the extended format, which has an odd LI (X.224 §13.7.4 NOTE), and LI 0, 1 and 3. On encode, `(*DT).MarshalBinary` returns it for `Parameters` without a `DestinationRef` (X.224 §13.7.1 a) gives the class 0 and 1 format no variable part) and for a variable part of odd length, which would make LI odd |
| `ErrInvalidClassOption` | Class/option field is invalid |
| `ErrDuplicateKnownParameter` | Retained for compatibility; no longer returned (last-wins per X.224 13.2.3) |
| `ErrInvalidEDUserDataLength` | ED user data length is outside 1–16 octets |
| `ErrNilReceiver` | `MarshalBinary` called on nil `*CR` / `*CC` / etc. |
| `ErrMissingRequiredField` | Required encode field is missing or invalid, including a value that does not fit its wire field: a CDT above 15 (CR, CC, AK, RJ) or a TPDU-NR above 127 (DT, ED) |
| `ErrInvalidConfig` | TP0/ITOT service configuration is invalid |
| `ErrHandshake` | TP0 CR/CC handshake or open-state protocol validation failed, including a TPKT framing violation by the peer (the go-tpkt sentinel, e.g. `tpkt.ErrInvalidVersion`, stays matchable) |

---

## Connection sentinels

These are returned by `Connect`, `Accept`, `ReadTSDU`, and `WriteTSDU`.

| Sentinel | When returned |
|----------|---------------|
| `ErrEmptyTSDU` | Zero-length TSDU was rejected (local policy) |
| `ErrTSDUTooLarge` | TSDU exceeds `MaxTSDULength` |
| `ErrClosed` | Local `Close` was called, or the connection was aborted after I/O (e.g. a context that ended an operation after octets had moved, joined with `context.DeadlineExceeded` / `context.Canceled`). Also returned by `ReadTSDU` and `WriteTSDU` on a zero `Conn`, which does not come from `Connect` or `Accept` |
| `ErrDisconnected` | The stream went away: peer EOF, TCP reset, broken pipe, EOF inside a packet, or a connection timeout reported by the operating system (`ETIMEDOUT`: keep-alive or retransmission without an answer); not a local Close |
| `ErrConnectionRefused` | Peer sent a DR during the handshake |
| `ErrUnexpectedTPDU` | Received a TPDU that is not legal in the current phase |
| `ErrIncompleteTSDU` | EOF or connection abort while reassembling a multi-DT TSDU, or a protocol violation mid-TSDU (then joined with `ErrHandshake`) |

A context that ends `ReadTSDU` / `WriteTSDU` **before any octet** of the TSDU
crossed the stream (an idle read, a stalled first write, or waiting for another
caller's TSDU to finish) returns the bare `ctx.Err()`, not wrapped in
`ErrClosed`, and the connection stays usable. The context of one direction
never affects the other direction.

A write timeout depends on the stream:

| Stream passed to `Connect` / `Accept` | `WriteTSDU` whose context ends while it writes to the stream |
|---|---|
| `*tls.Conn` | The connection is aborted: `ErrClosed` joined with the context error, also when no octet was accepted. crypto/tls fails every write after one that timed out (`tls.Conn.SetWriteDeadline`), so the stream cannot write again. |
| Any other (`*net.TCPConn`, for example) | No octet of the TSDU accepted: the bare `ctx.Err()`, and the connection stays usable. Octets accepted: aborted with `ErrClosed` joined with the context error. |

go-cotp recognises the `*tls.Conn` type itself; a stream that wraps one in
another type is treated as "any other". A context that ends before `WriteTSDU`
writes (while it waits its turn) leaves the connection usable over either
stream, and so does an idle read timeout. After an abort, every later call and
`Close` return the same terminal error.

go-tpkt (v1.2.0 and later) refuses further use of a TPKT reader or writer
after an error inside a packet (`tpkt.ErrStreamMisaligned`). go-cotp ends the
connection at that first error, so later calls return its terminal error and
`tpkt.ErrStreamMisaligned` does not reach a caller.

Only a deadline that go-cotp armed on the stream for the caller's context
counts as that context ending. A connection timeout reported by the operating
system (`ETIMEDOUT`) is a disconnect whatever context the caller holds: it
matches `ErrDisconnected`, never `context.DeadlineExceeded`, and it ends the
connection, during the handshake and in the open state.

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

Returned by `ReadTSDU` and `WriteTSDU` when the stream goes away: peer EOF,
TCP reset, broken pipe, EOF inside a packet, or a connection timeout reported
by the operating system (`ETIMEDOUT`). `Connect` and `Accept` return it for a
peer EOF at a packet boundary and for such a connection timeout; another
stream failure during the handshake comes back as the stream's own error.
`Cause` is the underlying error (e.g. `io.EOF`).

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
    case errors.Is(err, cotp.ErrInvalidTPDUCode), errors.Is(err, cotp.ErrReservedTPDU):
        // a type code that X.224 does not define, or reserves
    }
}
```
