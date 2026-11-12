# Test vector

Copied byte for byte from the Firmline platform repository (brkt-cra), `tests/fixtures/ota/` and `tests/fixtures/device/`, commit `e0ca812`. Do not edit these files; if the platform contract changes, a new vector is generated there and copied here again. The private key was never saved, so the vector cannot be regenerated identically.

| File | Content |
|------|---------|
| `ota/manifest.json` | the exact signed bytes (UTF-8 JSON, no trailing newline), component `firmware`, version `1.4.3+build.7` |
| `ota/firmware.bin` | the release file: 1000 ASCII bytes, matching `sha256` and `size` of the manifest |
| `ota/signature-p1363.b64` | the ES256 signature as `r‖s` (64 bytes), base64: the contract format |
| `ota/signature-der.b64` | the same signature in DER, base64 |
| `ota/public-key.pem` | the P-256 public key (SubjectPublicKeyInfo) |
| `ota/offer.json` | the MQTT offer carrying the manifest and the P1363 signature |
| `device/status.json` | a status message |
| `device/result.json` | an update result for the vector's release |

Values:

- `kid` = `70203f39f1a767927b55ac11efeab380e9b452dd5dff073807eb1ee82d7dc623` (SHA-256 of the public key DER, hex)
- `sha256` of `firmware.bin` = `c344861c7dd2b9a3bfaa0f5f97b8155553cfe3c8d8128e43eef4511ab795372b`
- `tenant` = `11111111-2222-4333-8444-555555555555`
- `family` = `66666666-7777-4888-9999-aaaaaaaaaaaa`
