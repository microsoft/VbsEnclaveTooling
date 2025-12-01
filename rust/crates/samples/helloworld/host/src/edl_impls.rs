// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use test_host_gen::implementation::untrusted::Untrusted;

pub struct HostImpl{}

impl Untrusted for HostImpl {
    fn print(data: &String) -> () {
        println!("{}", data);
    }
}
