# TP0 conformance fixtures

Wire fixtures for the Class 0 / RFC 1006 TP0 profile. Each `.hex` file is one complete COTP TPDU (no TPKT header): lowercase hex octets, space-separated.

## Layout

| Directory | Contents |
|-----------|----------|
| `connect/` | Client CR variants (S7-style, MMS-style, preferred-max) |
| `accept/` | Matching CC confirmations |
| `data/` | Segmented Class 0 DT (non-EOT then EOT) |
| `reject/` | DR refusal and ER responses |

## Provenance

| Fixture | Kind | Profile / clause | Notes |
|---------|------|------------------|-------|
| `connect/s7_cr_tsap1024.hex` | generated | S7comm-style TP0: 2-byte TSAPs, `0xC0=0x0A` (1024) | Canonical `MarshalBinary`; SRC-REF non-zero (go-cotp TP0). Installed-base S7 often sends SRC-REF=0. |
| `accept/s7_cc_tsap1024.hex` | generated | Matching CC for S7-style CR | Selectors echoed; size 1024 |
| `connect/mms_cr_selectors.hex` | generated | MMS/ISO-style: selectors present, size omitted | Default/omitted-size path (RFC 1006) |
| `connect/preferred_max_cr.hex` | generated | Dual offer `0xC0` + `0xF0` | X.224 13.3.4 b)/c); units=8 → 1024 |
| `accept/preferred_max_cc.hex` | generated | Preferred-max CC | Confirms `0xF0` units=7 → 896 |
| `data/dt_seg_non_eot.hex` | generated | Class 0 DT, EOT=0 | X.224 13.7 minimal (`LI=2`) |
| `data/dt_seg_eot.hex` | generated | Class 0 DT, EOT=1 | Final segment of a two-DT TSDU |
| `reject/dr_refuse_congestion.hex` | generated | DR reason congestion at TSAP | Policy refuse (X.224 13.5) |
| `reject/er_invalid_parameter_value.hex` | generated | ER cause=3 | Identifiable Class 0 CR field error |

**Kinds:** `generated` = produced by go-cotp `MarshalBinary` (deterministic). `captured` = from a sanitized wire capture (none yet). `normative` = copied from a standards example (none yet).

## CI expectations

`tp0_fixture_test.go` loads every `.hex` under this tree, checks decode semantics, and asserts encode round-trip equals the fixture bytes for generated fixtures.
