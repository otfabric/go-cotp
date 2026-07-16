# go-cotp

[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-cotp.svg)](https://pkg.go.dev/github.com/otfabric/go-cotp)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/otfabric/go-cotp/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-cotp/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/otfabric/go-cotp/graph/badge.svg)](https://codecov.io/gh/otfabric/go-cotp)
[![Release](https://img.shields.io/github/v/release/otfabric/go-cotp?label=release)](https://github.com/otfabric/go-cotp/releases)

X.224 / COTP TPDU encode/decode for Go, for use over RFC 1006 (TPKT).

This library is part of the **otfabric** OT protocol stack. It implements the Connection-Oriented Transport Protocol (COTP) layer above [go-tpkt](https://github.com/otfabric/go-tpkt) and below application protocols such as [go-s7comm](https://github.com/otfabric/go-s7comm) and go-mms.

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

The package lives at repo root so the import path is `github.com/otfabric/go-cotp` (same style as `github.com/otfabric/go-tpkt`). Package name is `cotp`.

## Scope

- **In scope:** COTP TPDU parsing and encoding for all supported types (CR, CC, DT, DR, DC, ER, ED, AK, EA, RJ); parameter handling; protocol detection helpers.
- **Out of scope:** TPKT framing (use [go-tpkt](https://github.com/otfabric/go-tpkt)); full application protocols; TCP connection management.

## Usage

### Decoding a TPDU

Obtain a COTP payload from a TPKT frame (e.g. from `tpkt.Decode` on a raw packet, or `tpkt.Reader.ReadFrame` on a connection), then decode:

```go
import (
    "github.com/otfabric/go-cotp"
    "github.com/otfabric/go-tpkt"
)

// From a raw TPKT packet (e.g. TCP buffer):
payload, err := tpkt.Decode(tcpPacket)
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
// ... TypeDC, TypeER
}
```

### Extracting DT user data

For Data TPDUs, you can get the upper-layer payload without full decode:

```go
payload, err := cotp.ExtractUserData(cotpPayload)
if err != nil {
    return err // not a DT or decode error
}
// payload may alias the input; copy if retaining
```

### Building and sending

Construct a TPDU, marshal it, then send as a TPKT frame:

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
// Send over a connection using go-tpkt:
w := tpkt.NewWriter(conn)
_, err = w.WriteFrame(encoded)
```

Integration is **“call tpkt then cotp”**: use go-tpkt for framing; pass the resulting payload to go-cotp for decode/encode. No separate helper package is required for v1.

## Integration

The otfabric stack is:

**TCP → TPKT ([go-tpkt](https://github.com/otfabric/go-tpkt)) → COTP (go-cotp) → S7comm / MMS / …**

- **go-tpkt** handles RFC 1006 framing: `ReadFrame()` returns one COTP payload per call; `WriteFrame(payload)` sends one framed TPDU.
- **go-cotp** parses and builds COTP TPDUs (CR, CC, DT, DR, DC, ER, ED, AK, EA, RJ). Payloads are typically obtained via `tpkt.Decode(tcpPacket)` or `tpkt.Reader.ReadFrame(conn)`.
- Upper layers (e.g. **go-s7comm**) consume the contents of Data TPDUs: use `cotp.Decode(payload)` and then `msg.DT.UserData`, or `cotp.ExtractUserData(payload)` to pass the byte slice to the next protocol.

## Documentation

- [API.md](API.md) — Public API reference: functions, structs, constants, and errors.
- [RELEASE.md](RELEASE.md) — Release notes (v0.1.0 initial release).
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute, run tests, and submit changes.
- [LICENSE](LICENSE) — MIT.
- [SECURITY.md](SECURITY.md) — How to report security issues.
- [spec/README.md](spec/README.md) — X.224 / COTP specification references.

Runnable examples (decode and encode with tpkt) live in `example_test.go`; run them with `go test -run Example`.

### Test data and captures

Committed hex fixtures in **`testdata/unit/`** are used by unit and golden tests. Capture fixtures go in **`testdata/captures/`**; see [testdata/captures/README.md](testdata/captures/README.md) for format and how to add new captures.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
