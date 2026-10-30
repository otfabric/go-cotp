# Architecture

How go-cotp is built today. The design of the whole stack (what go-tpkt, go-cotp, go-s7comm and go-mms each own, and the target including TP2) is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); the frozen service contract is in [docs/TP0_API_DESIGN.md](docs/TP0_API_DESIGN.md).

## Layers

One public package at the repository root, `cotp`, with one non-standard dependency, `github.com/otfabric/go-tpkt`. There is no `internal/` tree.

```text
Consumer (go-s7comm, go-mms)
        | complete TSDUs
        v
TP0 service      connect.go accept.go conn.go tsdu.go open_dt.go
        |        handshake_validate.go size_nego.go size_profile.go
        |        reference_allocator.go deadline.go config.go
        v
TPDU codec       decode*.go encode*.go params.go wire.go types.go
        | TPDU octets
        v
go-tpkt          tpkt.Reader, tpkt.Writer
        |
meteredConn      deadline.go: counts octets per direction
        |
net.Conn         TCP, or TLS completed by the caller
```

The codec has no state and can be used without the service (`Decode`, `MarshalBinary`). Only `Connect`, `Accept` and `Conn` touch go-tpkt.

## Connection lifecycle

1. `Connect` and `Accept` own the `net.Conn` from the moment they are called: every failing exit closes it.
2. The handshake runs on the caller's goroutine. It validates the configuration, wraps the stream in `meteredConn`, builds the TPKT reader and writer, allocates a non-zero local reference from the process-wide `defaultRefs` allocator, and exchanges CR and CC (or DR or ER on refusal). It is the only phase that uses `SetDeadline`.
3. On success the parameters are frozen in `NegotiatedParameters` and the `*Conn` is open.
4. `ReadTSDU` reassembles DT segments into one TSDU; `WriteTSDU` splits one TSDU into DT segments. Anything else in the open state ends the connection (`open_dt.go`).
5. `Close`, or an abort, runs once (`Conn.finish`): it records the first terminal cause, closes the stream and releases the reference.

## Goroutines and ownership

go-cotp starts no goroutine: there is no `go` statement in production code. The only callback is the `context.AfterFunc` in `directionDeadline.arm`, which sets a past deadline on the direction of the operation whose context was cancelled, to interrupt a blocked read or write.

| State | Protected by |
|---|---|
| Whole read TSDU, whole write TSDU | `readMu`, `writeMu`: channel locks (`opLock`), so a caller waiting for its turn still honours its context |
| Deadline of one direction | `directionDeadline.mu`; orders a cancellation against `disarm` |
| Terminal cause and kind | `termOnce` (first cause wins), `termMu` |
| Connection state | `state`, atomic |
| Octet counts | `meteredConn`, atomic |
| Local reference | `refOnce`; the allocator has its own mutex |
| `negotiated` | frozen at construction; `Negotiated()` returns a copy |

The octet counts decide what a cancelled operation does: if no octet of the TSDU moved, the stream is still at a packet boundary, so the call returns `ctx.Err()` and the connection stays open; otherwise the connection is aborted.

## Platform backends

None. The package uses only the standard library and go-tpkt, over any `net.Conn`. `make cross` builds it without cgo for the platforms it lists; tests run on Linux in CI.
