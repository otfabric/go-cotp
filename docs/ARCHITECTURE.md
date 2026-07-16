# Target architecture — OT Fabric transport stack

**Status:** target / normative for stack design  
**Date:** 2026-07-16  

This document freezes the intended service boundaries for:

- [`github.com/otfabric/go-tpkt`](https://github.com/otfabric/go-tpkt)
- [`github.com/otfabric/go-cotp`](https://github.com/otfabric/go-cotp) (this repository)
- [`github.com/otfabric/go-s7comm`](https://github.com/otfabric/go-s7comm)
- [`github.com/otfabric/go-mms`](https://github.com/otfabric/go-mms)

It is **not** a claim about current implementation completeness. Today go-cotp is a TPDU codec plus a partial TP0 engine (connection core, `Connect`/`Accept`, segmented TSDUs; open-state error coverage and consumer migrations next). See [COMPLIANCE.md](COMPLIANCE.md) for evidence-based status.

## Principle

Each library exposes the **service provided by its protocol layer** and hides the wire mechanics of the layer below it.

| Layer | Provides to the layer above | Hides |
| --- | --- | --- |
| go-tpkt | Opaque TPDU bytes delimited by TPKT packets | TCP stream fragmentation / coalescing |
| go-cotp | Established COTP connection carrying **complete TSDUs** | TPDU codecs, CR/CC, DT segmentation, TP0 refusal/error handling, future TP2 DR/DC release, and TPKT |
| go-s7comm | S7 application services | COTP and TPKT |
| go-mms | Session / Presentation / ACSE / MMS | COTP and TPKT |

## Dependency graph

```
go-s7comm ───────┐
                 ├──► go-cotp ───► go-tpkt
go-mms ──────────┘
```

**Invariant:** go-s7comm and go-mms must **not** depend on go-tpkt in production stack code. They receive an established COTP transport connection that carries complete transport service data units (TSDUs).

Exceptions for go-tpkt imports outside go-cotp: examples, diagnostic tools, packet analyzers, and tests.

## Stack diagram

```
┌────────────────────────┐     ┌────────────────────────┐
│       go-s7comm        │     │         go-mms         │
│ S7 policy and services │     │ Session/Pres/ACSE/MMS  │
└───────────┬────────────┘     └────────────┬───────────┘
            │ complete TSDUs                │ complete TSDUs
            └──────────────┬────────────────┘
                           ▼
                ┌──────────────────────┐
                │       go-cotp        │
                │ X.224 codec + engine │
                │ TP0 / TP2 service    │
                └──────────┬───────────┘
                           │ raw TPDUs
                           ▼
                ┌──────────────────────┐
                │       go-tpkt        │
                │ RFC 1006/2126 framing│
                └──────────┬───────────┘
                           ▼
                     TCP / TLS stream
```

---

## 1. go-tpkt

### Responsibility

Owns only the four-byte TPKT packet framing (RFC 1006 and applicable RFC 2126 framing policy):

```
TCP byte stream
      ↓
TPKT packet boundaries
      ↓
opaque TPDU bytes
```

It does not interpret COTP beyond documentation and protocol length constraints.

### Owns

**Buffer codec**

- `EncodePacket(payload []byte) ([]byte, error)`
- `DecodePacket(packet []byte) ([]byte, error)`

Version, reserved octet, total length, big-endian length, min/max TPKT length, exact-one-packet validation, trailing-byte rejection, reserved ignored on input / zero on output.

**Stream framing**

- `Reader.ReadPacket() ([]byte, error)`
- `Writer.WritePacket(payload []byte) error`

TCP fragmentation, coalesced TPKTs, one TPKT per call, short writes, partial header/payload, protocol-aware EOF, configured max packet length, framing resource bounds.

**Framing errors** — invalid version/length, oversize, payload too short/large, truncated packet, nil reader/writer.

### Does not own

TCP dial/listen, port 102, TLS, deadlines/reconnect, COTP type codes, CR/CC, TSAPs, classes, segmentation, references, S7/MMS data.

### Public abstraction

TPKT packet payload in / TPKT packet payload out. Nothing above or below that.

---

## 2. go-cotp

go-cotp owns **two** surfaces:

1. A complete COTP **TPDU codec**
2. A COTP **transport protocol engine** exposing X.214-style transport-service semantics

Today this repository mostly provides (1). Surface (2) is the primary architectural gap.

### A. TPDU codec

Owns all X.224 wire structures: CR, CC, DR, DC, DT, ED, AK, EA, RJ, ER — type codes, fixed/variable parts, LI, references, class/options, selectors, TPDU-size and preferred-max size, checksum/additional options, normal/extended formats, sequence/EOT/credit, reason/reject-cause, user-data placement, validation, unknown/duplicate parameter policy, deterministic encoding, malformed-input protection.

Conceptual API (names may evolve):

```go
tpdu, err := cotp.DecodeTPDU(raw)
raw, err := tpdu.MarshalBinary()
```

Codecs remain independently useful for inspection, fingerprinting, debugging, fixtures, analyzers, and custom engines.

### B. Protocol engine

Owns what is currently duplicated in go-s7comm and go-mms:

**Connection establishment** — CR/CC generation and validation, DR on refusal, reference allocation and matching, class/alternative-class negotiation, selector transport, TPDU-size and optional-feature negotiation, client/server state transitions.

**Connected data service** — TSDU → one or more DT TPDUs (segmentation, EOT), DT receive + reassembly → exactly one complete TSDU, negotiated max TPDU length, sequence/ack/flow control for applicable classes, expedited data where supported.

Consumers should **not** normally see DT TPDUs:

```go
err := conn.WriteTSDU(ctx, applicationBytes)
applicationBytes, err := conn.ReadTSDU(ctx)
```

Not:

```go
dt := &cotp.DT{EOT: true, UserData: applicationBytes}
raw, _ := dt.MarshalBinary()
tpktWriter.WritePacket(raw)
```

**Lifecycle** — TP0 stream-close release; handshake refusal and protocol-error handling (DR/ER as applicable); unexpected TPDU → abort; TCP closure mapping; partial-segment cleanup; future TP2 explicit DR/DC release.

**Classes (long-term)** — full common TPDU model; complete TP0; complete TP2 over RFC 2126; explicit representation or rejection of TP1/TP3/TP4.

### C. RFC 1006 / RFC 2126 profile

go-cotp is the **direct consumer of go-tpkt** and owns composition of COTP with TPKT over a stream:

```
COTP connection → COTP TPDU → go-tpkt Writer → net.Conn
net.Conn → go-tpkt Reader → COTP TPDU → engine / reassembly → complete TSDU
```

Owns: TPKT beneath COTP, TCP-close mapping, RFC 1006 TP0, RFC 2126 TP0/TP2 behavior, default-port metadata where useful, IPv4/IPv6 neutrality, TCP/TLS stream compatibility, profile-specific expedited-data mapping.

### D. Does not own

S7 rack/slot, Siemens connection types, MMS session SPDUs, presentation contexts, ACSE, MMS PDUs, S7 setup communication, PLC PDU sizes, IEC 61850 models, application request correlation, endpoint discovery, general TLS/certificate policy.

### Recommended public service abstraction

Exact names and rules are in **[TP0_API_DESIGN.md](TP0_API_DESIGN.md)** (architecture frozen; public API frozen; negotiation implementation-frozen; TP0 engine next).

Summary: `Connect` / `Accept` take ownership of a `net.Conn`, complete CR/CC, and return an open `*Conn` with `ReadTSDU` / `WriteTSDU` and a single `Close()` (TP0 T-DISCONNECT via stream close). Optional `Dial` is convenience only. Connect data is an **RFC 1006/ITOT profile** feature, not generic X.224 Class 0.

### Conceptual package layout

```
cotp/                 # codec today; + Connect/Accept/Conn service (P1 keeps codecs in root)
cotp/tpdu/            # optional later split of wire codecs
cotp/itot/            # RFC 1006 / 2126 profile adapters (or internal)
internal/state/       # TP0 / TP2 engines
```

Layout is guidance, not a mandatory first commit. P1: do not relocate codecs while implementing the engine.

---

## 3. go-s7comm

Owns Siemens S7 communication. Lower-layer input: **established COTP transport service**.

```
COTP TSDU → S7 PDU
```

### Owns

- Siemens connection types (PG/OP/S7 Basic), rack/slot encoding, TSAP derivation, S7 port defaults, TSAP overrides, probing/discovery
- Setup Communication, S7 PDU-size / AMQ negotiation (distinct from COTP TPDU-size)
- S7 headers, correlation, read/write, areas, SZL, blocks, CPU state, S7 errors, S7 PDU chunking
- Client host/port, retries, reconnect, timeouts, S7-level tracing

Produces selectors as opaque bytes for go-cotp; never teaches go-cotp what rack/slot means.

### Does not own

TPKT readers/writers, CR/CC, COTP references/classes, DT create/decode, EOT/segmentation, DR/DC/ER, COTP states.

### Desired path

```go
tcpConn, err := dial(...)
cotpConn, err := cotp.Connect(ctx, tcpConn, cotp.ClientConfig{
    LocalSelector:  s7LocalSelector,
    RemoteSelector: s7RemoteSelector,
    MaxTPDULength:  1024,
})
s7Client, err := s7.NewClient(cotpConn, options)

err := cotpConn.WriteTSDU(ctx, wire.EncodeS7Request(...))
response, err := cotpConn.ReadTSDU(ctx)
```

---

## 4. go-mms

Owns the application and upper OSI layers for MMS:

```
COTP transport service → Session → Presentation → ACSE → MMS
```

Session / Presentation / ACSE may remain **internal** to go-mms; they do not each require a separate repository.

### Owns

ISO 9506 MMS, ACSE association, presentation contexts, session SPDUs, MMS profile defaults (PSEL/SSEL, timeouts, auth), optional TLS policy in its convenience dialer.

Transport selectors are COTP values; MMS may supply profile defaults, then pass them to go-cotp.

### Does not own

TPKT, CR/CC, COTP references/classes, DT encode/decode, COTP segmentation, DR/DC lifecycle, RFC 1006 stream mapping.

### Desired path

```go
tcpConn, err := dial(...)
cotpConn, err := cotp.Connect(ctx, tcpConn, cotp.ClientConfig{
    LocalSelector:  mmsOptions.LocalTSelector,
    RemoteSelector: mmsOptions.RemoteTSelector,
})
sessionConn, err := session.Connect(ctx, cotpConn, sessionConfig)
presentationConn, err := presentation.Connect(ctx, sessionConn, presentationConfig)
association, err := acse.Associate(ctx, presentationConn, acseConfig)
client, err := mms.NewClient(association, mmsConfig)
```

---

## 5. TCP, TLS, deadlines

| Concern | Owner |
| --- | --- |
| Host/port, DNS, reconnect, interface, proxies, app connect timeout | Upper consumer (usually) |
| Optional `cotp.Dial` convenience | go-cotp (optional helper) |
| Core COTP engine input | Existing `net.Conn` / duplex stream |
| TLS config, trust, hostname verify, client certs | Consumer — TLS sits **TCP → TLS → TPKT → COTP** |
| Operation context / policy | Consumer |
| Read/write deadlines on the stream while COTP owns it | go-cotp |
| TPKT | Context-agnostic `io.Reader` / `io.Writer` |

Once a `net.Conn` is passed to go-cotp, **COTP has exclusive ownership** of protocol I/O. Upper libraries must not concurrently read, write, set deadlines, or frame packets on that connection.

---

## 6. Ownership matrix

| Concern | go-tpkt | go-cotp | go-s7comm | go-mms |
| --- | --- | --- | --- | --- |
| Four-byte TPKT header | Owns | Uses | No | No |
| TCP stream packet boundaries | Owns | Uses | No | No |
| COTP TPDU codecs | No | Owns | No* | No* |
| CR/CC handshake | No | Owns | No | No |
| COTP connection references | No | Owns | No | No |
| COTP classes | No | Owns | No | No |
| COTP TPDU-size negotiation | No | Owns | No | No |
| DT segmentation/reassembly | No | Owns | No | No |
| TP0 error/refusal lifecycle; future TP2 DR/DC release | No | Owns | No | No |
| Complete TSDU service | No | Provides | Uses | Uses |
| Siemens TSAP derivation | No | Opaque bytes | Owns | No |
| S7 Setup Communication | No | No | Owns | No |
| S7 PDU-size negotiation | No | No | Owns | No |
| S7 PDU codecs/services | No | No | Owns | No |
| Session / Presentation / ACSE | No | No | No | Owns |
| MMS PDU/services | No | No | No | Owns |
| IEC 61850 mapping | No | No | No | No (go-iec61850) |
| TLS configuration | No | Transparent stream | Consumer | Consumer |
| TCP dialing | No | Optional helper | Usually owns | Usually owns |
| Port defaults | No | Profile metadata | S7 default | MMS profile |
| Discovery/reconnect | No | No | Owns | MMS client policy |

\* Normal client/server paths must not build CR/CC/DT. Codec imports may remain for tests, tracing, diagnostics, or deliberate low-level APIs.

---

## 7. Dependency rules (architecture invariants)

1. **Only go-cotp** directly imports go-tpkt in production stack code (exceptions: examples, diagnostics, analyzers, tests).
2. **go-s7comm and go-mms** consume a COTP **service** abstraction, not TPDU codecs, in normal operation.
3. **go-cotp treats selectors as opaque** `[]byte`. S7 interprets rack/slot; MMS chooses profile selectors; COTP transports and applies selector equality/policy only.
4. **Each layer negotiates only its own size limit:**
   - TPKT `MaxPacketLength` — framing safety
   - COTP `MaxTPDULength` — transport negotiation
   - S7 PDU size — Siemens application negotiation
   - MMS local-detail / max-PDU — association negotiation  
   No silent reuse without an explicit conversion.
5. **Only one layer owns a connection’s read/write loop.** After the stream is given to go-cotp, consumers do not independently I/O that stream.

---

## Migration sequence

1. ~~Finish go-cotp **codec P0** fixes ([COMPLIANCE.md](COMPLIANCE.md)).~~ **Done** (v0.1.6).
2. Design the COTP **TP0 service API** → **[TP0_API_DESIGN.md](TP0_API_DESIGN.md)**.
3. ~~Typed Preferred Maximum codec + negotiation/handshake cases 1–60~~ **Done** (negotiation implementation-frozen).
4. ~~TP0 connection core + client `Connect` + server `Accept` + segmented TSDU + open-state errors~~ **Done**; next: go-s7comm migration.
5. RFC 1006 adapter is internal to go-cotp via go-tpkt (used by `Connect`).
6. Migrate go-s7comm from manual COTP to the new service (incl. real PLC non-zero SRC-REF check).
7. Migrate go-mms from its manual `transport/iso` implementation.
8. Remove production go-tpkt dependencies from go-s7comm and go-mms.
9. Implement TP2 / RFC 2126 without changing the consumer TSDU service abstraction.

## Clean boundary (summary)

- **TPKT** provides packets.
- **COTP** provides transport service data units.
- **S7comm / MMS** provide application protocols.
