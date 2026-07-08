# mbedTLS C++ enclave feasibility

This note records the initial mbedTLS feasibility study for the C++ TLS enclave sample.

## Scope

The goal is to determine whether mbedTLS can be used by a VTL1 C++ enclave sample where VTL0 provides only transport callbacks. This phase does not vendor mbedTLS source and does not add the final C++ sample project.

## Spike result

Result: **feasible**. The follow-on P4 work now builds mbedTLS into a VBS enclave DLL and drives a TLS 1.3 server-auth handshake from VTL1 through VTL0 TCP callbacks.

The spike used mbedTLS `v3.6.3` from a temporary clone and built the library sources with Visual Studio Build Tools in host mode. A custom config based on `include\mbedtls\mbedtls_config.h` removed host I/O and trusted-time assumptions:

```text
MBEDTLS_NET_C                  unset
MBEDTLS_FS_IO                  unset
MBEDTLS_HAVE_TIME              unset
MBEDTLS_HAVE_TIME_DATE         unset
MBEDTLS_TIMING_C               unset
MBEDTLS_PSA_ITS_FILE_C         unset
MBEDTLS_PSA_CRYPTO_STORAGE_C   unset
```

With those switches, the mbedTLS library C sources compiled with `cl` as C17 and `/MT`. A smoke executable initialised `psa_crypto_init`, `mbedtls_ssl_context`, `mbedtls_ssl_config`, `mbedtls_ctr_drbg_context`, and `mbedtls_entropy_context`, seeded CTR_DRBG through `mbedtls_entropy_func`, linked after adding `bcrypt.lib`, and printed `3.6.3`.

The expected `bcrypt.lib` dependency is compatible with the existing enclave sample projects, which already link BCrypt for enclave crypto support.

The follow-on `TlsEnclave` project proves that mbedTLS links as part of a VBS enclave DLL with `IgnoreAllDefaultLibraries`, `/ENCLAVE`, `/INTEGRITYCHECK`, `/GUARD:MIXED`, static CRT, `vertdll.lib`, BCrypt, and the enclave UCRT libraries.

## Host API check

The compiled objects were inspected for concrete unresolved socket, filesystem, and wall-clock APIs. No unresolved references were found for:

```text
socket
connect
recv
send
fopen
fread
fwrite
fclose
time
gmtime
localtime
CreateFile
QueryPerformance
GetSystemTime
```

This supports the intended VTL1 model: mbedTLS should use application-provided BIO callbacks for encrypted bytes, not built-in networking or file I/O.

The check was performed against host-mode object files. It is a useful early filter, not a substitute for an enclave link.

## Security consequences of the config

Disabling `MBEDTLS_HAVE_TIME` and `MBEDTLS_HAVE_TIME_DATE` means mbedTLS will not enforce certificate `notBefore` or `notAfter` validity periods. This is intentional for the first sample because the enclave has no trusted time source and uses pinned server identity. The sample must not claim browser-equivalent certificate freshness or revocation checking.

`MBEDTLS_PSA_CRYPTO_C` remains enabled. mbedTLS 3.6 TLS 1.3 depends on PSA crypto, so the C++ server-auth sample must initialise PSA before the handshake.

`MBEDTLS_TIMING_C` should remain disabled for the sample. Handshake and I/O progress should be driven by enclave logic and VTL0 transport callbacks, not by mbedTLS timing helpers that assume host wall-clock APIs.

## Integration recommendation

For the next C++ sample branch:

1. Acquire mbedTLS source outside the committed tree, pinned to an explicit version.
2. Compile mbedTLS source directly into a sample-local static library or project with an enclave-specific config header.
3. Keep the config owned by the sample so later branches can audit security-relevant options.
4. Link `bcrypt.lib` and use the enclave-compatible BCrypt RNG path for entropy.
5. Use mbedTLS send/recv callbacks backed by `TlsTransport.edl` host callbacks.

Avoid using an unconfigured prebuilt mbedTLS package for the enclave sample. The enclave build needs explicit control over sockets, filesystem, time, storage, entropy, and TLS feature selection.

## Open work for the C++ server-auth sample

- Add negative tests for wrong server certificate/pin and TLS 1.2-only server rejection.
- Add fragmentation and would-block transport tests.
- Consider reducing mbedTLS features and buffer sizes for enclave footprint.
- Decide whether the committed sample should keep checked-in generated C++ bindings or switch back to build-time codegen once package restore is reliable.
- Add a negative test showing the sample fails when the pinned server identity does not match.
- Document a single-thread-per-connection contract unless mbedTLS threading callbacks are configured. Note that `MBEDTLS_PSA_CRYPTO_C` keeps process-global state (the RNG and key slots), so a single-thread-*per-connection* rule is not sufficient on its own when several connections run concurrently: either enforce a single active session at a time, initialise/free PSA once for the enclave lifetime (reference-counted), or enable `MBEDTLS_THREADING_C` with enclave-backed mutex callbacks. The C++ sample reference-counts PSA init/free and serialises its enclave session table.

## Reproduction notes

The spike was performed from a temporary mbedTLS clone and did not add third-party source to the repository:

```text
git clone --depth 1 --branch v3.6.3 https://github.com/Mbed-TLS/mbedtls.git %TEMP%\tls-mbedtls-spike\mbedtls
```

Compilation used the Visual Studio Build Tools `vcvars64.bat`, `cl`, and `lib` tools. The smoke program linked against the temporary mbedTLS static library and `bcrypt.lib`, then printed `3.6.3`.

The tag resolved to commit `22098d41c6620ce07cf8a0134d37302355e1e5ef` during the spike. Future committed acquisition should pin the exact commit and update `NOTICE.md` as required by the mbedTLS Apache-2.0 licence.
