# Specification References

This repository is implemented against the original normative protocol specifications. The documents in `spec/` form the primary reference corpus used for protocol implementation, compliance verification, API design, and AI-assisted development.

## Specification hierarchy

| Specification | Purpose |
| --- | --- |
| [ITU-T X.214 (1995)](#itu-t-x214-1195) | Defines the OSI Connection-Oriented Transport Service, including the service primitives and semantics exposed to transport users. Guides the public API and transport service behavior. |
| [ITU-T X.224 (1995)](#itu-t-x224-1195) | Defines the Connection-Oriented Transport Protocol (COTP): TPDU formats, protocol procedures, transport classes, negotiation, state machines, and conformance. **Primary protocol specification for this library.** |
| [ITU-T X.224 Amendment 1 (1997)](#itu-t-x224-amendment-1-0897) | Updates X.224 with relaxed class conformance rules and expedited-data feature negotiation. Part of the normative protocol specification. |
| [RFC 1006](#rfc-1006) | Maps ISO Transport Class 0 onto TCP using TPKT framing. Defines how COTP operates over TCP/IP — the primary Internet profile implemented by this library. |
| [RFC 2126](#rfc-2126) | Updates and extends RFC 1006 with the Internet Transport over TCP (ITOT) profile: Class 2 support, IPv4/IPv6 considerations, interoperability guidance, and updated transport behavior over TCP. |

## Directory layout

```
spec/
├── README.md          # This file
├── core/              # ITU-T Recommendations (PDF)
│   ├── T-REC-X.214-199511-I!!PDF-E.pdf
│   ├── T-REC-X.224-199511-I!!PDF-E.pdf
│   └── T-REC-X.224-199708-I!Amd1!PDF-E.pdf
└── tcp/               # Internet profiles (plain text)
    ├── rfc1006.txt
    └── rfc2126.txt
```

---

## ITU-T X.214 (11/95)

**Transport Service Definition**

| | |
| --- | --- |
| Recommendation | [itu.int/rec/T-REC-X.214](https://www.itu.int/rec/T-REC-X.214/) |
| Overview | [T-REC-X.214-199511-I](https://www.itu.int/rec/T-REC-X.214-199511-I/en) |
| PDF (ITU-T) | [Download](https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.214-199511-I!!PDF-E&type=items) |
| **Local copy** | [core/T-REC-X.214-199511-I!!PDF-E.pdf](core/T-REC-X.214-199511-I!!PDF-E.pdf) |

---

## ITU-T X.224 (11/95)

**Connection-Oriented Transport Protocol (COTP)**

| | |
| --- | --- |
| Recommendation | [itu.int/rec/T-REC-X.224](https://www.itu.int/rec/T-REC-X.224/) |
| Overview | [T-REC-X.224-199511-I](https://www.itu.int/rec/T-REC-X.224-199511-I/en) |
| PDF (ITU-T) | [Download](https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.224-199511-I!!PDF-E&type=items) |
| **Local copy** | [core/T-REC-X.224-199511-I!!PDF-E.pdf](core/T-REC-X.224-199511-I!!PDF-E.pdf) |

---

## ITU-T X.224 Amendment 1 (08/97)

**Amendment 1 to Recommendation X.224**

| | |
| --- | --- |
| Overview | [T-REC-X.224-199708-I!Amd1](https://www.itu.int/rec/T-REC-X.224-199708-I!Amd1/en) |
| PDF (ITU-T) | [Download](https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.224-199708-I!Amd1!PDF-E&type=items) |
| **Local copy** | [core/T-REC-X.224-199708-I!Amd1!PDF-E.pdf](core/T-REC-X.224-199708-I!Amd1!PDF-E.pdf) |

---

## RFC 1006

**ISO Transport Service on top of the TCP**

| | |
| --- | --- |
| RFC Editor | [RFC 1006](https://www.rfc-editor.org/rfc/rfc1006) |
| Datatracker | [datatracker.ietf.org/doc/rfc1006](https://datatracker.ietf.org/doc/rfc1006/) |
| **Local copy** | [tcp/rfc1006.txt](tcp/rfc1006.txt) |

---

## RFC 2126

**ISO Transport Service on top of TCP (ITOT)**

| | |
| --- | --- |
| RFC Editor | [RFC 2126](https://www.rfc-editor.org/rfc/rfc2126) |
| Datatracker | [datatracker.ietf.org/doc/rfc2126](https://datatracker.ietf.org/doc/rfc2126/) |
| **Local copy** | [tcp/rfc2126.txt](tcp/rfc2126.txt) |

---

## Notes

- The ITU-T Recommendations are the canonical normative protocol specifications for this repository. Equivalent ISO/IEC publications ([ISO/IEC 8072](https://www.iso.org/standard/16335.html) and [ISO/IEC 8073](https://www.iso.org/standard/16336.html)) are not included here because they contain substantially the same technical content but are commercially licensed.
- [RFC 1006](#rfc-1006) and [RFC 2126](#rfc-2126) define the Internet profiles for operating COTP over TCP. They complement the ITU-T specifications rather than replacing them.
- Local PDF copies mirror the ITU-T published editions; local RFC `.txt` files are plain-text copies suitable for search and tooling.
