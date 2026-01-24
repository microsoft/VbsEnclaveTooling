# ETW Support for VBS Enclaves

The SDK enables the use of the [Tracelogging Rust Crate](https://crates.io/crates/tracelogging)
inside VBS Enclaves. When providers are registered with the SDK, it manages
provider registration and deregistration, and transparently forwards ETW calls between the
enclave and the host. No additional integration steps are required.

## Enclave Usage

### 1. Add dependencies

```toml
[dependencies]
tracelogging = { version = "1.2.4", features = ["macros", "etw", "kernel_mode"] }
vbsenclave-sdk-enclave = "0.1.0"
```

### 2. Define an ETW provider

```rust
// Use the tracelogging crate inside your enclave. 
// See: 
use tracelogging;

tracelogging::define_provider!(
    HELLO_WORLD_PROVIDER,
    "HelloWorldProvider",
);

// Now you can use the Tracelogging crates `write_event` macro to send events using
// that provider throughout your codebase!
```

### 3. Register the provider at DLL load

Register SDK exports and add the provider in your `DllMain`:

```rust
use core::ffi;

// Export SDK enclave functions at least once using the
// export_sdk_enclave_functions macro. Usually in your lib.rs.
vbsenclave_sdk_enclave::export_sdk_enclave_functions!();

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(instance: *const c_void, reason: u32, reserved: *mut c_void,
) -> bool {
    
    // DLL_PROCESS_ATTACH
    if reason == 1 {
        // Add a provider or list of providers.
        vbsenclave_sdk_enclave::etw::add_provider(&HELLO_WORLD_PROVIDER);
    }

    true
}
```

## Host Usage

### 1. Add dependencies

```toml
[dependencies]
vbsenclave-sdk-host = "0.1.0"
```

### 2. Register SDK callbacks after enclave is loaded and initialized

```rust
use vbsenclave_sdk_host::enclave::EnclaveHandle;
use vbsenclave_sdk_host::enclave;

let enclave_handle = EnclaveHandle::create_and_initialize(
        "enclave.dll",
        enclave::megabytes(256),
        None,
        0
)?;

// Call at least once after enclave initialization.
vbsenclave_sdk_host::register_sdk_callbacks(enclave_handle.as_ptr())?;
```

### 3. Unregister providers during teardown

> [!Note]
> When an enclave is created or owned via the SDK's `EnclaveHandle` smart pointer,
> ETW providers are automatically unregistered as part of enclave teardown.
> Otherwise, you will need to call `unregister_etw_providers` manually like below.

Before terminating and deleting the enclave:

```rust
vbsenclave_sdk_host::unregister_etw_providers(enclave)?;
```

The HelloWorld sample [here](https://github.com/microsoft/VbsEnclaveTooling/tree/main/rust/edlcodegen/crates/samples/helloworld)
demonstrates this usage.
