## Requirements
1. Install `rustup` for Windows [here](https://rust-lang.org/tools/install/).
1. Setup the machine you want to load the enclave on via the
   [prepare your dev environment](https://github.com/microsoft/VbsEnclaveTooling/blob/main/docs/HelloWorldWalkthrough.md#prepare-your-dev-environment)
   section in our documentation.
1. Confirm the Microsoft VC redistributable runtime is installed on the machine loading the enclave.
   The installer can be found here: 
   1. [x64](https://aka.ms/vs/17/release/vc_redist.x64.exe)
   1. [arm64](https://aka.ms/vs/17/release/vc_redist.arm64.exe)
1. Confirm you have installed the Windows SDK version `10.0.26100.3916` or higher
   on your build machine.

## How to build both the host and enclave
1. Run the `generate_and_build_crates.ps1` script in a PowerShell window.
   The script takes two arguments:
   - **Configuration**: either `release` or `debug` (default is `debug`).
   - **CertName**: the certificate name to sign the enclave with. This is
     optional. Note: This certificate should be added to the machine you
     plan to run your vbs enclave in as well.

   When executed, the script generates a crate named `<namespace>_gen` inside a
   folder called `generated` for both the host and the enclave. Each project
   references this crate through its own `Cargo.toml`. The `<namespace>` value
   comes from the `--namespace` argument passed to `edlcodegen.exe` inside the
   script.

### How to use the host and enclave
- The built `enclave.dll` and `host.exe` will both be in `target/<configuration>/`.

Place both binaries in the same directory on a machine that meets the
dev environment requirements above, then run `host.exe` from a terminal window.

Your output should look similar to the example below:
![Hello world sample](helloworld_sample.png)

### Where is the intellisense for the host and enclave projects?
1. Open the `HelloWorld` Rust workspace in a separate VSCode window by opening the
   `rust/crates/samples/helloworld` folder as it is not apart of the main `rust/`
   workspace. The Rust Analyzer should now provide you with intellisense.
