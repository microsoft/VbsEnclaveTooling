### Purpose of this crate
As of `01/15/2026`, the `windows-rs` crate has not yet been updated to
support Windows SDK `10.0.26100.7463`. Under normal circumstances, we
would consume the required WinRT APIs directly from windows-rs.
However, the `User Bound Key / KeyCredentialManager APIs` needed by
this project are not currently available there.

This crate serves as a temporary stopgap that provides bindings for
the missing APIs so they can be consumed by other crates. The bindings
in this crate are created using the `windows-bindgen` crate.

The `vbsenclave-sdk-host` crate depends on this crate in order to
access Windows Hello / Key Credential Manager functionality,
specifically the following APIs:

1. [OpenAsync](https://learn.microsoft.com/uwp/api/windows.security.credentials.keycredentialmanager.openasync?view=winrt-26100#windows-security-credentials-keycredentialmanager-openasync(system-string-windows-security-credentials-challengeresponsekind-windows-security-credentials-attestationchallengehandler))
1. [RequestCreateAsync](https://learn.microsoft.com/uwp/api/windows.security.credentials.keycredentialmanager.requestcreateasync?view=winrt-26100#windows-security-credentials-keycredentialmanager-requestcreateasync(system-string-windows-security-credentials-keycredentialcreationoption-system-string-system-string-windows-security-credentials-keycredentialcacheconfiguration-windows-ui-windowid-windows-security-credentials-challengeresponsekind-windows-security-credentials-attestationchallengehandler))
1. [GetSecureId](https://learn.microsoft.com//uwp/api/windows.security.credentials.keycredentialmanager.getsecureid?view=winrt-26100#windows-security-credentials-keycredentialmanager-getsecureid)

### Example Usage
```Rust

use userboundkey_kcm::{ KeyCredentialManager, ChallengeResponseKind };

pub fn establish_session_for_create(
    enclave: usize,
    key_name: &HSTRING,
    ecdh_alg: usize,
    message: &HSTRING,
    window_id: u64,
    cache: (u32, u64, u32),
    creation_option: KeyCredentialCreationOption,
) -> Result<(usize, SessionHandle)> {
    
    // parameter setup

    let result = KeyCredentialManager::RequestCreateAsync2(
        key_name,
        creation_option,
        &algorithm,
        message,
        &cache_cfg,
        WindowId { Value: window_id },
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        &callback,
    )?
    .GetResults()?;

    // further function statements
}
```

