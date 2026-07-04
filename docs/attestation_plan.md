# Attestation plan for TLS enclave samples

This document records the plan for adding Microsoft Azure Attestation (MAA) to the TLS enclave samples.

The end goal is for a web server to release protected data only after it has verified that the TLS peer is an approved VTL1 enclave. VTL0 remains an untrusted transport provider: it may connect sockets and move bytes, but it must not see the protected server payload.

## Background

Azure Attestation is a service for remotely verifying trusted execution environments, including VBS enclaves. The service receives attestation evidence, evaluates it against policy, and returns a signed JWT containing attestation claims.

For VBS enclave attestation, the most relevant public sample is:

```text
https://github.com/microsoft/Attestation-Client-Samples
```

The sample named `sample_enclave_att.exe` performs VBS enclave attestation and retrieves an attestation token from MAA. It uses:

- a VBS enclave DLL,
- TPM-backed attestation,
- an Attestation Identity Key (AIK),
- the `att_manager` APIs,
- the Azure Attestation C++ SDK.

Important sample files:

```text
attestation\sample_enclave_att.cpp
attestation\attest.cpp
attestation\attest.h
enclave\sample_enclave.cpp
```

The sample enclave exports wrappers around these VTL1 attestation routines:

```cpp
att_enclave_configure
att_enclave_create_session
att_enclave_attest
att_enclave_get_report
att_enclave_close_session
```

The sample host constructs an `att_enclave_function_table` containing those exports and passes it into `att_create_session`.

The sample's MAA exchange loop calls:

```cpp
att_attest(session, received_from_server, ..., &send_to_server, ..., &complete)
```

and sends `send_to_server` to MAA using:

```cpp
auto att_client = AttestationClient::Create(get_maa_provider_uri(), client_secret_cred);
auto response = att_client.AttestTpm(vector<uint8_t>(data, data + size));
return response.Value.TpmResult;
```

This implies that for VBS enclave attestation we should expect a TPM/AIK-backed, possibly multi-round attestation protocol, not a single "POST enclave report blob" flow.

## Required local/client pieces

The client machine or VM needs:

- VBS enabled.
- A TPM available.
- A signed and loadable enclave DLL.
- An AIK enrolled and accessible to the host process.
- Attestation client dependencies:
  - `att_manager`
  - Azure Attestation SDK
  - Azure Identity SDK
  - WIL

The public sample expects these environment variables:

```text
AZURE_TENANT_ID
AZURE_CLIENT_ID
AZURE_CLIENT_SECRET
AZURE_MAA_URI
```

The AIK setup in the sample is:

```powershell
EnrollAik.ps1 att_sample_aik -AclIdentity BUILTIN\Users
```

Notes:

- The public sample warns that AIK enrollment may not work on some VMs because a virtual TPM may not have a trusted endorsement key certificate accepted by Azure Certificate Services.
- We need to verify this on our target VM before designing around the public sample's exact AIK flow.

## Required server pieces

The web server must be able to:

1. Generate a fresh per-session nonce.
2. Receive attestation protocol messages from the client.
3. Either call MAA itself or verify an MAA token returned by the client.
4. Validate the MAA JWT signature using the MAA OpenID metadata/signing certificates.
5. Validate JWT claims:
   - issuer is the expected MAA provider,
   - token is fresh,
   - nonce matches the current server challenge,
   - enclave identity/signing/policy claims match the server allowlist,
   - policy result is acceptable.
6. Release protected data only after validation succeeds.

## Integration options

### Option A: Client calls MAA, server verifies token

Flow:

1. Enclave opens TLS to server.
2. Server sends a fresh challenge nonce.
3. Client/host performs MAA attestation.
4. Client sends the MAA JWT/token to server over the TLS channel.
5. Server verifies the token and claims.
6. Server releases protected data.

Pros:

- Simpler server.
- Closest to the public sample shape.

Cons:

- Azure credentials or MAA access are needed on the client/host.
- Server must be very careful to verify issuer/provider and all claims.
- Less production-like, because the server delegates the MAA call to an untrusted client.

### Option B: Web server proxies attestation to MAA

Flow:

1. Server sends a fresh challenge nonce.
2. Client/enclave creates the next attestation protocol blob.
3. Client sends the blob to the web server.
4. Web server calls MAA.
5. Web server sends any MAA response blob needed by the client attestation state machine.
6. Repeat until attestation completes.
7. Server verifies final MAA token/claims.
8. Server releases protected data.

Pros:

- Azure credentials stay server-side.
- Server controls the MAA provider and policy.
- Server is the relying party and directly decides whether to release data.
- Better production shape.

Cons:

- More server work.
- Must carry the multi-round `att_attest` exchange through our application protocol.

Recommendation: use **Option B** for the real sample. Option A is acceptable as a short bootstrap spike only if needed.

## Binding attestation to the TLS session

The server must avoid accepting a replayed attestation token from another session.

The challenge should include or derive from:

```text
H(
  server_nonce ||
  server_name ||
  requested_resource ||
  TLS exporter/channel binding ||
  optional enclave public key
)
```

The attestation result must prove that this challenge was included in the enclave-held or relying-party data that MAA validated.

If TLS exporter support is not immediately available in mbedTLS/rustls, stage the binding:

1. First bind to server nonce + resource + server name.
2. Then add TLS exporter/channel binding before claiming session-bound attestation.

## What the server should verify

The server should verify:

| Check | Purpose |
|---|---|
| MAA JWT signature | Proves token came from MAA. |
| MAA issuer | Ensures the expected provider produced the token. |
| Token time bounds | Rejects stale tokens. |
| Server nonce | Prevents replay. |
| Enclave identity/signing claims | Allows only approved enclave images/signers. |
| Policy claims/result | Ensures the MAA provider policy accepted the evidence. |
| Channel binding/exporter claim | Binds attestation to this TLS session. |
| Optional enclave public key claim | Binds future server-issued credentials or data to an enclave-held key. |

## Staged implementation plan

### A0: Run and understand the public MAA VBS sample

Goals:

- Build and run `microsoft/Attestation-Client-Samples`.
- Confirm AIK enrollment works on our VM.
- Capture the final MAA token shape.
- Record exact claims emitted for our VBS enclave path.
- Confirm which Azure credentials and MAA provider setup are required.

Deliverable:

```text
SampleApps\Tls\AttestationFeasibility.md
```

Contents should include:

- exact commands used,
- required environment variables,
- AIK setup notes,
- token/JWT claim names,
- policy observations,
- blockers.

### A1: Add attestation exports to the TLS enclave

Add enclave exports equivalent to the public sample:

```cpp
sample_att_enclave_configure
sample_att_enclave_create_session
sample_att_enclave_attest
sample_att_enclave_get_report
sample_att_enclave_close_session
```

For our TLS sample these can be renamed, but should wrap the same `att_manager` enclave routines.

Deliverable:

- `TlsEnclave.dll` can participate in the `att_manager` enclave attestation session.

### A2: Add server-side attestation endpoints

Extend the test server with an attestation state machine. Candidate endpoints:

```text
GET  /attestation/challenge
POST /attestation/exchange
GET  /secret-config
```

For Option B, `/attestation/exchange` forwards client attestation blobs to MAA and returns MAA response blobs until complete.

Deliverable:

- Server owns nonce generation and MAA calls.
- Server stores attestation state for the TLS/session/client.

### A3: Bind attestation to the TLS session

Add challenge data that includes:

- server nonce,
- requested resource,
- server identity,
- TLS exporter/channel binding when available.

Deliverable:

- Attestation token cannot be replayed across sessions without detection.

### A4: Gate `/secret-config` on attestation

Change the server so `/secret-config` only returns protected payload after successful attestation.

Deliverable:

- No attestation: request denied.
- Valid attestation: protected payload returned.
- VTL0 still only sees encrypted TLS records.

### A5: Negative tests

Add tests for:

- no attestation,
- stale nonce,
- wrong enclave identity,
- wrong MAA provider/issuer,
- replayed token,
- token without expected policy result,
- valid token bound to another TLS session,
- VTL0 transport corruption or truncation.

## Open questions

1. Does AIK enrollment work on our target VM?
2. What exact MAA attestation type and endpoint does the VBS enclave sample use in our environment?
3. Which MAA claims identify VBS enclave image, signer, product, version, and security version?
4. What policy should the MAA provider use for our sample enclave?
5. Do we want a client-calls-MAA bootstrap mode, or go directly to server-proxies-MAA?
6. Can we get TLS exporter/channel binding cleanly from mbedTLS and rustls in the sample?
7. How should the server represent attested session state: cookie, connection-local state, bearer token, or in-memory test map?

## Recommended next step

Start with A0:

1. Build and run the public `sample_enclave_att.exe`.
2. Confirm AIK enrollment and MAA provider access.
3. Save a real MAA JWT.
4. Decode and document the claims.
5. Decide exact server-side policy and validation rules before adding endpoints to the TLS sample server.
