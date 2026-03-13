# Capture fixtures

Committed fixtures in this directory are **required in CI**: the test decodes each `.hex` file and asserts no error.

## Adding captures

1. **Format:** One COTP TPDU per file, hex-encoded (space-separated or contiguous). Same format as `testdata/unit/` (e.g. as exported from Wireshark or `xxd`).
2. **Sanitization:** Redact or trim sensitive payloads and addresses before committing. Do not commit customer-sensitive data.
3. **Provenance:** Document source in the filename or a comment (e.g. `s7comm_cr.hex` from S7 handshake). Do not expose identifying or sensitive details.
4. **Naming:** Use descriptive names: `cr_*.hex`, `cc_*.hex`, `dt_*.hex`, etc.

## Local / experimental captures

Developer-local captures that are not yet sanitized or reviewed should stay outside this directory (e.g. in a local folder or gitignored path). Promote to committed fixtures only after sanitization and provenance documentation.
