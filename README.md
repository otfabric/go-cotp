# go-cotp

[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-cotp.svg)](https://pkg.go.dev/github.com/otfabric/go-cotp)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/otfabric/go-cotp/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-cotp/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/otfabric/go-cotp)](https://goreportcard.com/report/github.com/otfabric/go-cotp)
[![Codecov](https://codecov.io/gh/otfabric/go-cotp/graph/badge.svg)](https://codecov.io/gh/otfabric/go-cotp)
[![Release](https://img.shields.io/github/v/release/otfabric/go-cotp?label=release)](https://github.com/otfabric/go-cotp/releases)

X.224 / COTP TPDU encode/decode for Go, for use over RFC 1006 / RFC 2126 TPKT framing.

This library is part of the **otfabric** OT protocol stack. It implements a **COTP TPDU codec** above [go-tpkt](https://github.com/otfabric/go-tpkt) and below application protocols such as [go-s7comm](https://github.com/otfabric/go-s7comm) and [go-mms](https://github.com/otfabric/go-mms).

It is **not yet** a complete X.214 transport service or X.224 protocol engine (no connection state machine, class negotiation, or segmentation/reassembly). The **target** is for go-cotp to own both the TPDU codec and a COTP engine that exposes complete TSDUs to [go-s7comm](https://github.com/otfabric/go-s7comm) and [go-mms](https://github.com/otfabric/go-mms), with go-tpkt used only inside go-cotp. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## Table of contents

- [Install](#install)
- [Scope](#scope)
- [Usage](#usage)
  - [Decoding a TPDU](#decoding-a-tpdu)
  - [Extracting DT user data](#extracting-dt-user-data)
  - [Building and sending](#building-and-sending)
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

- **In scope today (codec):**
  - Encode/decode for all ten connection-oriented TPDU types: CR, CC, DT, DR, DC, ER, ED, AK, EA, RJ
  - Variable-part parameter TLV parsing; CR/CC typed selectors and TPDU-size parameter
  - DT minimal (class 0/1) and normal (class 2–4) formats; extended DT rejected
  - Classification helpers (`LooksLike*`) — **not** validators
- **In scope for v1 (engine — not yet implemented):**
  - X.214-style transport service (`Conn` Read/Write complete TSDUs)
  - TP0 (and later TP2) state machine, CR/CC negotiation, DT segment/reassembly, DR/DC/ER
  - RFC 1006 / RFC 2126 profile composition using go-tpkt internally
- **Out of scope (always):**
  - TPKT packet framing implementation (owned by [go-tpkt](https://github.com/otfabric/go-tpkt))
  - Application protocols (S7comm, MMS) and their selector/PDU policies
  - TLS trust policy, reconnect, and discovery (consumers)

## Usage

### Decoding a TPDU

Obtain a COTP payload from a TPKT packet (e.g. from `tpkt.DecodePacket` on a raw packet, or `tpkt.Reader.ReadPacket` on a connection), then decode. **Do not** pass an entire TPKT packet to `cotp.Decode`.

```go
import (
    "github.com/otfabric/go-cotp"
    "github.com/otfabric/go-tpkt"
)

// From a raw TPKT packet (e.g. TCP buffer):
payload, err := tpkt.DecodePacket(tcpPacket)
if err != nil {
    return err
}
msg, err := cotp.Decode(payload)
if err != nil {
    return err
}
switch msg.Type {
case cotp.TypeCR:
    fmt.Println("Connection Request:", msg.CR)
case cotp.TypeCC:
    fmt.Println("Connection Confirm:", msg.CC)
case cotp.TypeDT:
    fmt.Println("Data, user bytes:", len(msg.DT.UserData))
case cotp.TypeDR:
    fmt.Println("Disconnect Request:", msg.DR)
// ... TypeDC, TypeER, TypeED, …
}
```

### Extracting DT user data

For Data TPDUs, you can get the upper-layer payload without full decode:

```go
payload, err := cotp.ExtractUserData(cotpPayload)
if err != nil {
    return err // not a DT/ED or decode error
}
// payload may alias the input; copy if retaining
```

### Building and sending

Construct a TPDU, marshal it, then send as a TPKT packet:

```go
cr := &cotp.CR{
    CDT:            0,
    DestinationRef: 0,
    SourceRef:      0,
    ClassOption:    0,
}
encoded, err := cr.MarshalBinary()
if err != nil {
    return err
}
// Send over a connection using go-tpkt v1:
w, err := tpkt.NewWriter(conn)
if err != nil {
    return err
}
err = w.WritePacket(encoded)
```

Integration is **“call tpkt then cotp”**: use go-tpkt for framing; pass the resulting TPDU byte slice to go-cotp for decode/encode.

## Integration

**Today (codec):** callers obtain one TPDU from go-tpkt, then call `cotp.Decode` / `MarshalBinary`.

**Target (service boundaries):**

```
go-s7comm / go-mms
        │  complete TSDUs
        ▼
     go-cotp          ← owns codec + TP0/TP2 engine; only production importer of go-tpkt
        │  raw TPDUs
        ▼
     go-tpkt
        │
   TCP / TLS stream
```

- **go-tpkt** owns TPKT framing only (opaque TPDU payloads).
- **go-cotp** will own CR/CC, DT segmentation/reassembly, DR/DC/ER, and an X.214-style `Conn` (`Read`/`Write` complete TSDUs). Selectors are opaque `[]byte`.
- **go-s7comm / go-mms** own application protocols and selector *policy*; they must not depend on go-tpkt in production paths once the COTP service exists.
- Size limits stay layer-local: TPKT max packet ≠ COTP max TPDU ≠ S7 PDU size ≠ MMS max PDU.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full ownership matrix and migration sequence.

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

Committed hex fixtures in **`testdata/unit/`** are used by unit and golden tests. Capture fixtures go in **`testdata/captures/`**; see [testdata/captures/README.md](testdata/captures/README.md) for format and how to add new captures.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
