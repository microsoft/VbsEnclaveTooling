## Requirements
1. Install `rustup` for Windows [here](https://rust-lang.org/tools/install/).
1. Install the [`Rust Analyzer`](https://rust-analyzer.github.io/) in your favorite
   code editor for intellisense. We recommend [VSCode](https://code.visualstudio.com/docs/languages/rust).
1. Install Rustfmt `rustup component add rustfmt`
1. Install Clippy `rustup component add clippy`

## How to build the SDK crates
1. Run the `<repo-root>\rust\sdk\generate_and_build_crates.ps1` script in
   a PowerShell window. 
   The script takes only argument:
   - **Configuration**: either `release` or `debug` (default is `debug`).
1. This will also format your code using `rustfmt`. This is needed to pass
   the build checks in the Github PR pipeline.

## Before pull request submission
- Run `cargo clippy --workspace --all-targets -- -D warnings` in
  `<repo-root>\rust\sdk` and fix any errors that may occur. Without
  this, the pull request pipeline checks may fail since clippy is ran
  during the pipeline workflow.
