# COTP / X.224 notes for implementers

This document is a practical, implementation-oriented guide for this repository.

It does **not** replace the official specifications. It exists to make the protocol easier to understand and to define the subset and behavior this library implements.

## Normative references

Primary protocol references:

- **ITU-T X.224 (1995)** / **ISO/IEC 8073** — Connection-mode transport protocol specification (spec/T-REC-X.224-199511-I!!PDF-E.pdf)
- **ITU-T X.224 Amendment 1 (1997)** — additional conformance / expedited-data updates (spec/T-REC-X.224-199708-I!Amd1!PDF-E.pdf)
- **RFC 1006** — ISO transport services on top of TCP, using TPKT framing (handled by https://github.com/otfabric/go-tpkt)

In practical TCP-based OT stacks, the usual layering is:


TCP
└── TPKT (RFC 1006)
    └── COTP / X.224
        └── Application protocol
            ├── S7comm
            ├── MMS / IEC 61850 MMS
            └── others

What COTP is

COTP is the OSI transport protocol used above a network service and below an application protocol.

In modern OT practice over Ethernet/TCP, COTP is commonly seen encapsulated inside:
	•	TCP
	•	TPKT
	•	then application-layer payloads such as S7comm or MMS

For this repository, the practical goal is:
	•	encode and decode core COTP TPDUs
	•	expose clean Go types and helpers
	•	support protocol detection and higher-layer handoff
	•	provide a stable base for other OT libraries

Scope of this repository

This library is intended to be a clean reusable COTP layer, not a monolithic Siemens-only or IEC 61850-only implementation.

In scope
	•	COTP TPDU type definitions
	•	TPDU encode/decode
	•	parameter parsing and serialization
	•	connection request / confirm handling
	•	data TPDU handling
	•	disconnect / error handling
	•	helpers useful for protocol detection and upper-layer dispatch
	•	robust validation and descriptive errors

Out of scope
	•	TPKT framing itself
	•	full application-layer protocol parsing
	•	TCP connection management policy
	•	scan engines or device fingerprinting logic
	•	vendor-specific S7 or MMS behavior beyond generic transport concerns

Those belong in sibling repositories.

Design goals

This repository should be:
	•	small
	•	composable
	•	standards-grounded
	•	transport-layer focused
	•	easy to test thoroughly
	•	safe to use in protocol scanners and production clients

The library should be suitable for:
	•	go-s7comm
	•	go-mms
	•	future go-ot-probe style detection tooling
	•	pcap decoders
	•	replay and fuzzing tools

Core terminology

Transport protocol data unit (TPDU)

A TPDU is the protocol unit exchanged by COTP.

Examples include:
	•	CR — Connection Request
	•	CC — Connection Confirm
	•	DR — Disconnect Request
	•	DC — Disconnect Confirm
	•	DT — Data
	•	ED — Expedited Data
	•	AK — Data Acknowledgement
	•	EA — Expedited Acknowledgement
	•	RJ — Reject
	•	ER — Error

Not all of these are equally important for OT-over-TCP use cases.

For most practical industrial stacks over TCP/TPKT, the critical subset is:
	•	CR
	•	CC
	•	DT
	•	DR
	•	DC
	•	ER

TPDU type

Each TPDU has a type code in its header. This is the main discriminator during decode.

Variable part / parameters

Some TPDUs, especially CR and CC, contain a variable parameter section.

Typical parameters include things like:
	•	source transport selector
	•	destination transport selector
	•	TPDU size
	•	class / options

For OT usage, these parameters are important because many higher-level protocols rely on them during connection establishment.

User data

For data-bearing TPDUs, the user data is the payload passed upward to the next layer, such as:
	•	S7comm PDU
	•	MMS PDU

Practical subset for OT over TCP

This repo should focus first on the subset most useful for real TCP/TPKT traffic.

Phase 1: essential TPDUs

Implement first:
	•	CR — Connection Request
	•	CC — Connection Confirm
	•	DT — Data
	•	DR — Disconnect Request
	•	DC — Disconnect Confirm
	•	ER — Error

This is enough to support:
	•	S7comm transport setup
	•	MMS transport setup
	•	protocol detection above TPKT
	•	passive decode of many real captures

Phase 2: optional TPDUs

Implement later as needed:
	•	ED
	•	AK
	•	EA
	•	RJ

These matter less for typical OT TCP traces but should still have type definitions reserved cleanly.

Repository package layout

Recommended package split:

go-cotp
├── cotp          # public API: TPDU encode/decode, core types
├── x224          # optional protocol constants / naming helpers
├── detect        # optional lightweight helpers for protocol detection
├── internal/...  # parsing helpers, bounds checks, shared validation
└── spec          # normative notes and implementation profiles

A minimal public surface is better than many shallow packages.

A simpler alternative is:

go-cotp
├── cotp
└── spec

That is usually the better v1.

Recommended public API style

Prefer strong typed APIs over loose maps.

Example shape:
	•	Type enum for TPDU types
	•	TPDU interface only if it adds real value
	•	concrete structs for each TPDU
	•	Decode([]byte) (Message, error)
	•	(Message) MarshalBinary() ([]byte, error)

Good examples:
	•	CR
	•	CC
	•	DT
	•	DR
	•	DC
	•	ER

If an interface is used, it should stay small:

Type() TPDUType
MarshalBinary() ([]byte, error)

Do not over-engineer with inheritance-style abstractions.

Recommended wire model

The library should model the protocol as it appears on the wire after TPKT has already been removed.

That means decode input should normally be:
	•	exactly one COTP packet payload
	•	not raw TCP stream bytes
	•	not including TPKT header bytes

This keeps responsibilities clean:
	•	go-tpkt handles TPKT framing
	•	go-cotp handles X.224 TPDU parsing
	•	upper-layer libs handle application payloads

Connection-oriented workflow

Typical TCP/TPKT/COTP sequence:

1. TCP connection established

A TCP socket is opened to the target, commonly port 102.

2. TPKT frame received/sent

RFC 1006 wraps the transport payload.

3. COTP CR sent

The initiator sends a Connection Request TPDU.

4. COTP CC received

The responder accepts and returns a Connection Confirm TPDU.

5. Data transfer begins

Application PDUs are exchanged inside DT TPDUs.

6. Optional disconnect / error

DR/DC/ER may appear on shutdown or invalid protocol situations.

What upper layers usually care about

Upper-layer protocols usually do not want to understand every transport nuance.

They mostly need:
	•	whether connection setup succeeded
	•	extracted transport selectors or options
	•	the application payload from DT
	•	meaningful errors when transport negotiation fails

This library should therefore make these operations easy.

Detection-oriented helpers

Because you care about protocol auto-detection, this library should expose helpers that support classification without embedding scanner logic.

Useful helpers:
	•	LooksLikeCR([]byte) bool
	•	LooksLikeCC([]byte) bool
	•	PeekType([]byte) (TPDUType, error)
	•	IsConnectionOriented([]byte) bool
	•	ExtractUserData([]byte) ([]byte, error)

These should remain lightweight and deterministic.

They are especially useful when building tools that classify:
	•	raw TCP payload
	•	TPKT payload
	•	COTP handshake vs data
	•	candidate upper protocol

Errors

Error behavior should be explicit and descriptive.

Prefer sentinel errors plus wrapped detail.

Examples:
	•	ErrTooShort
	•	ErrInvalidLI
	•	ErrUnknownTPDUType
	•	ErrMalformedParameter
	•	ErrUnexpectedParameterLength
	•	ErrUnsupportedTPDU
	•	ErrInvalidClassOption

Then wrap with context:
	•	decode CR: invalid LI
	•	decode CC: malformed TPDU size parameter
	•	decode DT: payload truncated

Do not silently accept malformed wire input.

Validation principles

On decode:
	•	reject truncated headers
	•	reject impossible length indicators
	•	reject malformed parameter blocks
	•	reject trailing overrun / underflow inconsistencies
	•	preserve unknown-but-valid information where possible

On encode:
	•	validate required fields
	•	validate parameter lengths
	•	produce canonical output where practical
	•	never emit structurally invalid TPDUs

Unknown and vendor-specific behavior

Industrial devices are often imperfect.

The library should therefore distinguish between:
	•	invalid
	•	unknown but structurally valid
	•	unsupported by this library

Unknown parameters should usually be preserved rather than discarded, when possible.

That supports:
	•	passive decode
	•	replay
	•	round-trip encoding
	•	future extension without breaking behavior

Round-trip behavior

A useful rule for v1:
	•	if a TPDU is valid and fully understood, decode then re-encode should preserve the wire form or produce a semantically equivalent canonical form
	•	unknown parameters should be preserved where feasible
	•	malformed frames must not round-trip as if valid

Testing expectations

The library should aim for very high test coverage.

Required test categories:

Unit tests
	•	TPDU type detection
	•	CR decode
	•	CC decode
	•	DT decode
	•	DR/DC/ER decode
	•	parameter parsing
	•	encode/decode round trips
	•	error cases for truncated and malformed input

Table-driven tests

Every decoder should have:
	•	valid minimal case
	•	valid common case
	•	malformed short case
	•	malformed length mismatch case
	•	unknown parameter case
	•	unsupported TPDU case

Fuzz tests

Add fuzz targets for:
	•	generic TPDU decode
	•	CR decode
	•	CC decode
	•	DT decode

Goal:
	•	no panics
	•	no out-of-bounds behavior
	•	deterministic error handling

Golden tests

Use golden hex vectors for well-known real traffic patterns, especially:
	•	S7comm CR/CC over TPKT
	•	MMS/IEC 61850 style COTP connection setup if available

Interop profile for v1

The initial implementation target should be:
	•	connection-oriented mode only
	•	core TPDUs only
	•	TCP/TPKT carriage use cases
	•	strong support for OT protocol handoff

This is enough for most immediate consumers.

Non-goals for v1

Do not block v1 on:
	•	every transport class nuance in X.224
	•	full expedited-data behavior
	•	every rarely used TPDU
	•	full OSI service semantics beyond what appears on the wire
	•	heavy session state machines

Start with clean wire parsing and encoding first.

Relationship to sibling repositories

Recommended sibling repo structure:

go-tpkt   # RFC 1006 framing
go-cotp   # X.224 / ISO transport TPDU layer
go-s7comm # Siemens S7 application layer
go-mms    # MMS application layer

This separation is good because it lets you reuse stack layers across multiple OT protocols.

Suggested first milestone

A strong first milestone for this repo is:
	•	decode TPDU type
	•	encode/decode CR
	•	encode/decode CC
	•	encode/decode DT
	•	extract DT payload
	•	preserve unknown parameters
	•	full table-driven tests
	•	fuzz tests for decode entrypoints
	•	short README examples

Suggested second milestone

Then add:
	•	DR / DC / ER
	•	detection helpers
	•	canonical parameter types
	•	better pretty-print helpers for debugging
	•	golden vectors from real captures

Suggested third milestone

Then add:
	•	optional TPDUs
	•	more interop vectors
	•	passive decoder helpers
	•	upper-layer handoff examples for S7comm and MMS

Implementation philosophy

This repository should favor:
	•	correctness over cleverness
	•	small APIs over broad APIs
	•	typed structs over generic maps
	•	explicit validation over permissive guessing
	•	reusable transport primitives over product-specific shortcuts

Short mental model

When thinking about this library, use this model:
	•	go-tpkt answers: “do I have one RFC1006 packet?”
	•	go-cotp answers: “what transport TPDU is this, and what does it contain?”
	•	upper-layer libraries answer: “what application protocol is inside the transport payload?”

That separation is exactly what will help you build a clean OT protocol stack family over time.

