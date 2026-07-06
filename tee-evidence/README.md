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

Run one backend at a time. The command writes `evidence.json` in this
directory.

```bash
cargo run --features virtcca-attester
cargo run --features itrustee-attester
cargo run --features csv-user-attester
cargo run --features csv-kernel-attester
```

No attester backend is built by default. Select the backend for the current
machine explicitly. Do not enable multiple hardware backends unless all native
libraries and devices for those backends are present.

Default evidence requests are initialized from the enabled backend feature:

- `virtcca-attester`: `uuid = None`, `ima = None`, raw challenge length = 64 bytes.
- `itrustee-attester`: `uuid = Some(DEFAULT_UUID)`, `ima = None`, raw challenge length = 64 bytes.
- `csv-user-attester` / `csv-kernel-attester`: `uuid = None`, `ima = None`, raw challenge length = 16 bytes.

The raw challenge bytes are base64url encoded before being stored in
`EvidenceRequest.challenge`, matching the verifier decoding paths.

## Huawei VirtCCA

```bash
cargo run --features virtcca-attester
```

The VirtCCA verifier can verify the generated `evidence.json` with:

```bash
cd ../evidence-verify
cargo run --features virtcca-verifier -- ../tee-evidence/evidence.json
```

For local reference verification, use `no_as` on the verifier side:

```bash
cargo run --features "virtcca-verifier no_as" -- ../tee-evidence/evidence.json
```

The local VirtCCA reference value file is:

```text
/etc/attestation/attestation-agent/local_verifier/virtcca/ref_value.json
```

Its minimal format is:

```json
{
  "rim": "<expected vcca.cvm.rim hex>"
}
```

If the evidence contains `event_log`, the verifier also needs an event
reference file. With `no_as`, the path is:

```text
/etc/attestation/attestation-agent/local_verifier/virtcca/event/digest_list_file
```

Without `no_as`, verifier files are read from:

```text
/etc/attestation/attestation-service/verifier/virtcca/
```

## Huawei iTrustee

```bash
cargo run --features itrustee-attester
```

The iTrustee verifier can verify the generated `evidence.json` with:

```bash
cd ../evidence-verify
cargo run --features itrustee-verifier -- ../tee-evidence/evidence.json
```

The verifier links the native `teeverifier` library:

```text
libteeverifier.so
```

Make sure the runtime linker can find it, for example:

```bash
export LD_LIBRARY_PATH=/path/to/libteeverifier:$LD_LIBRARY_PATH
```

The iTrustee reference value file is selected by the UUID inside the evidence:

```text
/etc/attestation/attestation-service/verifier/itrustee/itrustee_<uuid>
```

## Hygon CSV

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
cargo run --features csv-user-attester
cargo run --features csv-kernel-attester
```

Run the two Hygon CSV backends separately. Do not enable `csv-user-attester`
and `csv-kernel-attester` in the same command.

`build.rs` selects the native build flags from the enabled feature:

- `csv-user-attester`: links libcrypto with `-lcrypto`.
- `csv-kernel-attester`: compiles the C shim with `-fno-stack-protector` and links `/usr/lib/libcrypto.a -lc -lpthread`.

Override the static libcrypto path for kernel mode when needed:

```bash
CSV_LIBCRYPTO_A=/path/to/libcrypto.a cargo run --features csv-kernel-attester
```

If GmSSL is not installed in `/opt/gmssl`, set:

```bash
CSV_GMSSL_INCLUDE=/path/to/include CSV_GMSSL_LIB=/path/to/lib cargo run --features csv-kernel-attester
```

Verify the generated CSV evidence with:

```bash
cd ../evidence-verify
cargo run --features csv-user-verifier -- ../tee-evidence/evidence.json
cargo run --features csv-kernel-verifier -- ../tee-evidence/evidence.json
```

The CSV verifier uses OpenSSL/GmSSL `libcrypto` for SM3 and elliptic-curve
operations. The verifier constructs the SM2 curve parameters itself, so it does
not require OpenSSL to register the `SM2` curve name, but `MessageDigest::sm3()`
must be available.
