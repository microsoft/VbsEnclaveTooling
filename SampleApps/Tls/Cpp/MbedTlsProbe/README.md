# mbedTLS enclave link probe

This project is the first C++ server-auth gate: it proves mbedTLS can compile and link into a VBS enclave DLL with enclave linker settings.

It does not perform a TLS handshake yet. It initialises PSA crypto, SSL context/config objects, entropy, and CTR_DRBG inside an enclave-shaped DLL export.

## Build

```powershell
.\Build-MbedTlsProbe.ps1 -Configuration Debug -Platform x64
```

The build script fetches pinned mbedTLS source into `SampleApps\Tls\external\mbedtls`, which is intentionally ignored by git.

## Notes

- mbedTLS is pinned by commit in `..\..\Fetch-MbedTls.ps1`.
- The project excludes mbedTLS networking, timing, and PSA file-storage sources.
- The config disables mbedTLS sockets, filesystem I/O, wall-clock validation, timing helpers, and PSA file storage.
- `bcrypt.lib` is linked for the default Windows entropy poll path.
- The x64 Debug probe has been validated with VS Build Tools 18 (`v145`) and links with `/ENCLAVE`, `/INTEGRITYCHECK`, `/GUARD:MIXED`, `IgnoreAllDefaultLibraries`, enclave CRT libraries, and `bcrypt.lib`.
