# Security

## Reporting a vulnerability

If you believe you have found a security vulnerability in this project, please report it responsibly.

- **Do not** open a public GitHub issue for security-sensitive bugs.
- Email **security@otfabric.io**, or open a **private security advisory** on GitHub: **Security** → **Advisories** → **Report a vulnerability**.

Include a clear description, steps to reproduce, affected versions, and the impact. We will acknowledge your report and work with you on a fix and disclosure timeline.

## Resource limits

What go-cotp bounds on the input it takes from a peer, with the default, the place that enforces it and the test that pins it. A consumer that reads from peers it does not control sets `MaxTSDULength` to what its application protocol needs and gives every call a context with a deadline.

| Limit | Default | Where enforced | Test |
| --- | --- | --- | --- |
| TPKT packet (header and payload) | 4 to 65535 octets, the range of the 16-bit length field | go-tpkt `Reader.ReadPacket`, before the payload is allocated; a packet with another version or a length below the header ends the connection with `ErrHandshake` | `TestFramingErrorClassification`, `TestFramingErrorDuringHandshake` |
| Received TPDU | the negotiated `MaxTPDULength`: 128 to 65531 octets, 65531 when not configured | `decodeOpenDT` (`open_dt.go`), before the TPDU is decoded; a longer TPDU ends the connection with `ErrHandshake` | `TestTSDU_InboundExceedsNegotiatedMax`, `TestOpenState_TPDUExceedsNegotiatedMax`, `TestAdversarial_OversizedTPDU` |
| Reassembled TSDU | `MaxTSDULength`: 4 MiB (`DefaultMaxTSDULength`) when 0 | `ReadTSDU` (`tsdu.go`), before each segment is added; the octet over the limit ends the connection with `ErrTSDUTooLarge`. `WriteTSDU` refuses a longer TSDU before any I/O | `TestReadTSDU_SmallestSegmentsAtTheLimit`, `TestTSDU_InboundExceedsMaxTSDU`, `TestTSDU_ReassemblyBoundAbort`, `TestAdversarial_EndlessNonEOTHitsBound`, `TestTSDU_OneAboveMaxTSDURejectedBeforeWrite` |
| Segments of one TSDU | at most `MaxTSDULength`: a DT without user data is refused, so every segment adds an octet | `ReadTSDU` | `TestTSDU_EmptySegmentRejected` |
| Memory held by one `ReadTSDU` call | less than twice `MaxTSDULength`, plus one TPKT packet; `MaxTSDULength` plus one packet while it waits for a segment | `ReadTSDU`: one buffer, grown by doubling and capped at the limit, whatever the size and number of the segments | `TestReadTSDU_PendingReassemblyBudget` (allocation budget, default limit and 64 KiB) |
| Time a partly received TSDU is held | none of its own: until the context of that `ReadTSDU` ends | the caller's context, applied as the read deadline | `TestTSDU_ContextTimeoutAfterIOAborts`, `TestTSDU_LocalCloseMidReassembly` |
| Handshake time | none of its own: until the context of `Connect` or `Accept` ends | the caller's context, applied as the stream deadline for the handshake | `TestLifecycle_HandshakeContextEnds`, `TestLifecycle_HandshakeWithoutDeadlineWaits` |
| CR TPDU | 128 octets (`MaxCRTPDULength`, X.224 §13.3) | `DecodeCR`, `(*CR).MarshalBinary` | `TestDecodeCR`, `TestAdversarial_HandshakeOversizedCR` |
| Connect data in CR and CC | 32 octets (`MaxConnectDataLength`) | `Connect` and `Accept`: configuration, the received CR and the received CC | `TestServiceLimits`, `TestAccept_ConnectDataTooLargeBeforeCC`, `TestLifecycle_FailedConnectReleasesEverything` |
| TPDU header | 254 octets after the length indicator (`MaxLI`); a parameter value 255 octets | `ReadLI`, `headerBounds`, the parameter parsers: every length is checked against the octets present before it is used | `TestReadLI`, `TestDecode_EveryPrefixOfValidTPDUs`, `TestMarshal_ParameterValueLengthBound`, the `FuzzDecode*` targets |
| TPDU size offered or selected by the peer | the codes 0x07 to 0x10 of the TPDU size parameter (0xC0); 1 to 511 units of 128 octets (`MaxPreferredUnitsITOT`) in the preferred maximum (0xF0). The size in use never exceeds the local `MaxTPDULength` | `decodeSizeOffer`, `selectSize`, `interpretCCSize` (`size_nego.go`); another value fails the handshake | `TestDecodeSizeOffer_DualPreserve`, `TestGapInterpretCCSize`, `FuzzDecodeSizeOffer` |
| ED user data (codec) | 1 to 16 octets | `DecodeED`, `(*ED).MarshalBinary` | `TestDecodeED`, `TestED_MarshalBinary_UserDataRange` |
| Connections open at once in one process | 65535: each holds one non-zero 16-bit local reference | the reference allocator shared by `Connect` and `Accept`; at the limit they fail with `ErrInvalidConfig` | `TestGapReferenceAllocator`, `TestReferenceAllocator` |

What go-cotp does not bound, because the caller owns it:

- **Connections.** go-cotp accepts no connection itself; the caller's listener does. Bound the connections you admit: each one can hold the memory of one pending reassembly for as long as its read context allows.
- **Handshake and idle time.** `Connect`, `Accept`, `ReadTSDU` and `WriteTSDU` have no timeout of their own. With a context that has no deadline, a handshake or a read waits for as long as the peer stays silent, on the goroutine that called it. A server gives `Accept` a context with a deadline, as the server example in [README.md](README.md#tp0-server) does.
- **Goroutines.** go-cotp starts none. `ServerConfig.OnConnect` runs on the goroutine that called `Accept`.

What is not implemented or not verified is in [LIMITATIONS.md](LIMITATIONS.md).

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | Best effort |
