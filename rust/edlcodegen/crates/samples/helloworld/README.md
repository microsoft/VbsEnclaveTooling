## Requirements
1. Install `rustup` for Windows [here](https://rust-lang.org/tools/install/).
1. Install the [`Rust Analyzer`](https://rust-analyzer.github.io/) in your favorite
   code editor for intellisense. We recommend [VSCode](https://code.visualstudio.com/docs/languages/rust).
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

> [!NOTE]
> When executed, the script generates 2 crates. One for the host and one
> for the enclave. Each generated crate is placed inside a folder called
> `generated` within its respective project folder (host or enclave).
> Both the host and the enclave use their generated crate as a dependency
> in their `Cargo.toml` file.
> The generated crate name is prefixed with the value used as the `--namespace`
> argument given to `edlcodegen.exe` inside the script. In the case of this
> sample we used `test` as the namespace argument so the following crates
> are generated:
> 1. `test_enclave_gen` 
> 1. `test_host_gen`

### How to use the host and enclave
- The built `enclave.dll` and `host.exe` will both be in
  ```
  <repo-root>/rust/crates/samples/helloworld/target/<configuration>/
  ```

Place both binaries in the same directory on a machine that meets the
dev environment requirements above, then run `host.exe` from a terminal window.

Your output should look similar to the example below:
![Hello world sample](helloworld_sample.png)

### Where is the intellisense for the host and enclave projects?
- To get IntelliSense for the `helloworld` host and enclave crates, open the
   `helloworld` folder in its own VS Code window. You can do this by
   opening the following folder:

   ```
   <repo-root>/rust/crates/samples/helloworld
   ```

   Once opened, the Rust Analyzer will correctly activate and provide
   IntelliSense for both crates.
