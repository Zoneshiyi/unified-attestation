# tee-evidence

Minimal evidence generator extracted from `attestation-agent/attester`.

Kept attester backends:

- `itrustee`
- `virtcca`
- `csv_user`
- `csv_kernel`

Removed attester backends:

- `cca`
- `tsm_report`
- service/client/token/verifier architecture

IMA is fixed to `none`: evidence requests are created with `ima: Some(false)`,
so no IMA log is read or mixed into the nonce.

Run:

```bash
cargo run
```

No attester backend is built by default. Select the backend for the current
machine explicitly.

```bash
cargo run --features virtcca-attester
```

To build for iTrustee instead:

```bash
cargo run --features itrustee-attester
```

To build both backends, both native libraries must be available to the linker:

```bash
cargo run --features "itrustee-attester virtcca-attester"
```

Default evidence requests are initialized from the enabled backend feature:

- `virtcca-attester`: `uuid = None`, `ima = None`, raw challenge length = 64 bytes.
- `itrustee-attester`: `uuid = Some(DEFAULT_UUID)`, `ima = None`, raw challenge length = 64 bytes.
- `csv-user-attester` / `csv-kernel-attester`: `uuid = None`, `ima = None`, raw challenge length = 16 bytes.

The raw challenge bytes are base64url encoded before being stored in
`EvidenceRequest.challenge`, matching the backend decoding paths.

Run the two Hygon CSV backends separately; do not enable
`csv-user-attester` and `csv-kernel-attester` in the same command.

## Hygon CSV evidence

Hygon CSV has two attestation collection paths, matching the vendor C demo:

- `csv-user-attester`: user-mode `vmmcall`; requires access to `/proc/self/pagemap`.
- `csv-kernel-attester`: kernel-assisted ioctl through `/dev/csv-guest`; preferred in Kata/container environments where pagemap access is restricted.

The low-level C code is kept under:

- `src/csv_user`
- `src/csv_kernel`

Both paths produce a JSON evidence payload with:

- `mode`: `user` or `kernel`
- `report`: base64 encoded Hygon CSV attestation report
- `nonce`: base64url encoded 16-byte CSV mnonce derived from the request challenge
- `ima_log`: optional IMA log, currently `null` unless IMA support is enabled later

Build on Linux x86_64 with OpenSSL/GmSSL libcrypto available. The C shim uses
the generic EVP/HMAC API (`EVP_sm3`), so it does not require the GmSSL-only
`openssl/sm3.h` header.

```bash
cargo run --features csv-kernel-attester
cargo run --features csv-user-attester
```

If GmSSL is not installed in `/opt/gmssl`, set:

```bash
CSV_GMSSL_INCLUDE=/path/to/include CSV_GMSSL_LIB=/path/to/lib cargo run --features csv-kernel-attester
```
