// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod common;
use common::test_helpers::*;
use common::test_types::*;

#[cfg(test)]
mod core {
    use super::fb_generated::flatbuffer_test;
    use super::*;

    #[test]
    fn conversion_between_edl_types_and_flatbuffer_types() {
        let initial_edl_struct = create_all_types_struct();

        // Developer type -> Flatbuffer type
        let flatbuffer_struct: flatbuffer_test::AllTypesT = initial_edl_struct.clone().into();

        // Flatbuffer type -> Developer type
        let ending_dev_struct: dev_types::AllTypes = flatbuffer_struct.into();

        // Check that the dev type struct we ended up with is the same as the initial
        // struct to confirm we succeeded the round trip.
        assert_eq!(initial_edl_struct, ending_dev_struct);
    }
}
