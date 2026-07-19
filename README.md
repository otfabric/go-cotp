# go-cotp

[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-cotp.svg)](https://pkg.go.dev/github.com/otfabric/go-cotp)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/otfabric/go-cotp/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-cotp/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/otfabric/go-cotp/graph/badge.svg)](https://codecov.io/gh/otfabric/go-cotp)
[![Release](https://img.shields.io/github/v/release/otfabric/go-cotp?label=release)](https://github.com/otfabric/go-cotp/releases)

TP0 (Class 0) COTP transport service for Go over RFC 1006 TPKT, plus a full X.224 TPDU codec.

This library is part of the **otfabric** OT protocol stack. It sits above [go-tpkt](https://github.com/otfabric/go-tpkt) and below application protocols such as [go-s7comm](https://github.com/otfabric/go-s7comm) and [go-mms](https://github.com/otfabric/go-mms).

**Today:** a TP0 service API (`Connect` / `Accept` / `ReadTSDU` / `WriteTSDU` / `Close`) with CR/CC negotiation, selectors, segmentation/reassembly, and open-state protocol enforcement — plus the low-level TPDU codec. **Not** a complete X.214/X.224 engine (no TP2, expedited data service, or full RFC 2126). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/TP0_API_DESIGN.md](docs/TP0_API_DESIGN.md), and [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## Table of contents

- [Install](#install)
- [Scope](#scope)
- [Usage](#usage)
  - [TP0 client](#tp0-client)
  - [TP0 server](#tp0-server)
  - [Concurrency and ownership](#concurrency-and-ownership)
  - [Low-level TPDU codec](#low-level-tpdu-codec)
- [Integration](#integration)
- [Documentation](#documentation)
  - [Test data and captures](#test-data-and-captures)
- [License](#license)

## Install

```bash
go get github.com/otfabric/go-cotp
```

**Requires:** Go 1.23+

The package lives at repo root so the import path is `github.com/otfabric/go-cotp` (same style as `github.com/otfabric/go-tpkt`). Package name is `cotp`. Framing dependency: `github.com/otfabric/go-tpkt` **v1.0.0+**.

## Scope

- **In scope today (TP0 service):**
  - `Connect` / `Accept` / `ReadTSDU` / `WriteTSDU` / `Close` over an owned `net.Conn`
  - Class 0 CR/CC handshake, TPDU-size negotiation (standard + preferred-maximum profiles), selectors, connect data
  - Segmented TSDU transfer; open-state unexpected/malformed TPDU handling; TCP-close release
- **In scope today (codec):**
  - Encode/decode for all ten connection-oriented TPDU types: CR, CC, DT, DR, DC, ER, ED, AK, EA, RJ
  - Variable-part parameter TLV parsing; CR/CC typed selectors and TPDU-size parameter
  - DT minimal (class 0/1) and normal (class 2–4) formats; extended DT rejected
- **Not yet / out of v1 claim:**
  - TP2, expedited data service, full RFC 2126, native CONS/CLNS
- **Out of scope (always):**
  - TPKT packet framing implementation (owned by [go-tpkt](https://github.com/otfabric/go-tpkt))
  - Application protocols (S7comm, MMS) and their selector/PDU policies
  - TLS trust policy, reconnect, and discovery (consumers)

## Usage

```
go-cotp
├── TP0 transport service
│   ├── Connect
│   ├── Accept
│   ├── ReadTSDU
│   ├── WriteTSDU
│   └── Close
└── Low-level TPDU codec
    ├── Decode
    └── MarshalBinary
```

### TP0 client

```go
conn, err := net.Dial("tcp", "plc.example:102")
if err != nil {
    return err
}
cotpConn, err := cotp.Connect(ctx, conn, cotp.ClientConfig{
    LocalSelector:  []byte{0x01, 0x00},
    RemoteSelector: []byte{0x01, 0x01},
    MaxTPDULength:  1024,
})
if err != nil {
    return err // conn already closed on failure
}
defer cotpConn.Close()

if err := cotpConn.WriteTSDU(ctx, request); err != nil {
    return err
}
response, err := cotpConn.ReadTSDU(ctx)
```

For TLS: dial and complete `tls.Handshake` yourself, then pass the `*tls.Conn` to `Connect` / `Accept` (same ownership rules).

### TP0 server

```go
ln, err := net.Listen("tcp", ":102")
// ...
raw, err := ln.Accept()
cotpConn, err := cotp.Accept(ctx, raw, cotp.ServerConfig{
    LocalSelector: []byte{0x01, 0x01},
    MaxTPDULength: 1024,
    OnConnect: func(_ context.Context, ind cotp.ConnectIndication) (cotp.AcceptDecision, error) {
        // Inspect selectors / connect data; accept or reject with DR reason.
        return cotp.AcceptDecision{Action: cotp.ConnectAccept}, nil
    },
})
```

### Concurrency and ownership

- `Connect` / `Accept` take ownership of `conn` **immediately** (including on error).
- One reader + one writer may run concurrently on a `*Conn`.
- `Close` unblocks outstanding `Connect`/`Accept` waiters on the peer side and local `ReadTSDU`/`WriteTSDU`.
- If a context expires **after** I/O has started, the connection is aborted (not left half-open).
- Limits: `MaxTPDULength` ∈ `[128, 65531]` (0 → default 65531); `MaxTSDULength` caps reassembled TSDUs; connect data ≤ 32 octets.
- Compliance: TP0 / RFC 1006 Class 0 profile — not full X.214/X.224/RFC 2126. See [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

Runnable examples: `go test -run Example`.

### Low-level TPDU codec

For tooling that already has a COTP payload (e.g. from `tpkt.DecodePacket`), use `cotp.Decode` / `MarshalBinary`. **Do not** pass an entire TPKT packet to `Decode`.

```go
msg, err := cotp.Decode(payload)
encoded, err := (&cotp.CR{SourceRef: 1, TPDUSize: &size1024}).MarshalBinary()
```

## Integration

```
go-s7comm / go-mms
        │  complete TSDUs
        ▼
     go-cotp          ← TP0 service + codec; only production importer of go-tpkt
        │
     go-tpkt
        │
   TCP / TLS stream
```

- **go-tpkt** owns TPKT framing only.
- **go-cotp** owns CR/CC, DT segmentation/reassembly, open-state abort, and the TSDU `Conn` API. Selectors are opaque `[]byte`.
- **go-s7comm / go-mms** own application protocols and selector *policy*; they should not depend on go-tpkt once migrated.
- Size limits stay layer-local: TPKT max packet ≠ COTP max TPDU ≠ S7 PDU size ≠ MMS max PDU.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the ownership matrix.

## Documentation

- [docs/API.md](docs/API.md) — Public API reference: functions, structs, constants, and errors.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — Target stack service boundaries and dependency rules.
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md) — Standards compliance matrix and gap roadmap.
- [RELEASE.md](RELEASE.md) — Release notes.
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute, run tests, and submit changes.
- [LICENSE](LICENSE) — MIT.
- [SECURITY.md](SECURITY.md) — How to report security issues.
- [spec/README.md](spec/README.md) — X.214 / X.224 / RFC 1006 / RFC 2126 references.

Runnable examples (decode and encode with tpkt) live in `example_test.go`; run them with `go test -run Example`.

### Test data and captures

- **`testdata/tp0/`** — TP0 conformance fixtures (S7/MMS-style handshake, preferred-max, segmented DT, DR/ER); see [testdata/tp0/README.md](testdata/tp0/README.md).
- **`testdata/unit/`** — minimal per-type golden hex.
- **`testdata/captures/`** — sanitized wire captures; see [testdata/captures/README.md](testdata/captures/README.md).

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
