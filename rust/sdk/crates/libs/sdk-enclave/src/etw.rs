// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common;
use alloc::{collections::BTreeMap, vec::Vec};
use core::marker::PhantomData;
use sdk_enclave_gen::AbiError;
use sdk_enclave_gen::implementation::types as edl_types;
use sdk_enclave_gen::stubs::untrusted::{self};
use spin::{Once, RwLock};
use tracelogging::{Channel, Level, Opcode, Provider};

/// Information about a registered ETW provider.
/// The registration_id is generated during registration
/// and is used to look up the provider info during
/// the enablement callback from the etw framework.
struct EtwProviderInfo {
    provider_id: uuid::Uuid,
    registration_id: uuid::Uuid,
    callback: ProviderEnableCallback,
    callback_context: usize,
}

#[derive(Default)]
struct EtwRegistrationMap {
    table: BTreeMap<uuid::Uuid, EtwProviderInfo>,
}

fn etw_registration_map() -> &'static RwLock<EtwRegistrationMap> {
    static ETW_REGISTRATION_MAP: Once<RwLock<EtwRegistrationMap>> = Once::new();
    ETW_REGISTRATION_MAP.call_once(|| RwLock::new(EtwRegistrationMap::default()))
}

fn etw_providers() -> &'static RwLock<Vec<&'static Provider>> {
    static ETW_PROVIDERS: Once<RwLock<Vec<&'static Provider>>> = Once::new();
    ETW_PROVIDERS.call_once(|| RwLock::new(Vec::new()))
}

pub fn register_providers() {
    static REGISTER_PROVIDERS_ONCE: Once<()> = Once::new();
    REGISTER_PROVIDERS_ONCE.call_once(|| {
        for &provider in etw_providers().read().iter() {
            unsafe {
                provider.register();
            }
        }
    });
}

/// Adds a single ETW provider to be registered later.
/// The provider must have been create using the `tracelogging` crate.
pub fn add_provider(provider: &'static Provider) {
    etw_providers().write().push(provider);
}

/// Adds multiple ETW providers to be registered later.
/// The provider must have been create using the `tracelogging` crate.
pub fn add_providers(providers: &[&'static Provider]) {
    let mut etw_providers = etw_providers().write();
    for &provider in providers {
        etw_providers.push(provider);
    }
}

/// Unregisters all ETW providers added via `add_provider` or `add_providers`.
pub fn unregister_providers() {
    for provider in etw_providers().read().iter() {
        provider.unregister();
    }
}

#[repr(C)]
#[derive(Debug, Default)]
struct EventDataDescriptor<'a> {
    ptr: u64,
    size: u32,
    reserved: u32,
    lifetime: PhantomData<&'a [u8]>,
}

#[repr(C)]
#[derive(Debug, Default)]
struct EventFilterDescriptor<'a> {
    ptr: u64,
    size: u32,
    Type: u32,
    lifetime: PhantomData<&'a [u8]>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct EventDescriptor {
    id: u16,
    version: u8,
    channel: Channel,
    level: Level,
    opcode: Opcode,
    task: u16,
    keyword: u64,
}

fn uuid_to_abi(uuid: &uuid::Uuid) -> edl_types::Guid {
    let uuid_fields = uuid.as_fields();
    edl_types::Guid {
        data1: uuid_fields.0,
        data2: uuid_fields.1,
        data3: uuid_fields.2,
        data4: *uuid_fields.3,
    }
}

#[inline]
fn result_from_abi(result: Result<u32, AbiError>) -> u32 {
    if let Ok(code) = result {
        code
    } else {
        match result.err().unwrap() {
            AbiError::Win32Error(code) => code,
            // Can't convert HRESULT to Win32 error code directly,
            // return a generic error code.
            AbiError::Hresult(_) => 0x0000054F_u32, //ERROR_INTERNAL_ERROR
        }
    }
}

/// Implementation of declared ETW Unregister function called by the ETW framework.
/// See: https://github.com/microsoft/tracelogging/blob/rust1.2.4/etw/rust/tracelogging/src/native.rs#L468
#[unsafe(no_mangle)]
unsafe extern "system" fn EtwUnregister(reg_handle: u64) -> u32 {
    let result = untrusted::event_unregister(reg_handle);
    result_from_abi(result)
}

type ProviderEnableCallback = fn(
    source_id: &edl_types::Guid,
    event_control_code: u32,
    level: Level,
    match_any_keyword: u64,
    match_all_keyword: u64,
    filter_data: usize,
    callback_context: usize,
);

/// Implementation of declared ETW Register function called by the ETW framework.
/// See: https://github.com/microsoft/tracelogging/blob/rust1.2.4/etw/rust/tracelogging/src/native.rs#L469
#[allow(improper_ctypes_definitions)] // Callback is invoked in rust not C/C++
#[unsafe(no_mangle)]
unsafe extern "system" fn EtwRegister(
    provider_id: &edl_types::Guid,
    outer_callback: ProviderEnableCallback,
    outer_context: usize,
    reg_handle: &mut u64,
) -> u32 {
    // Use uuid crate to avoid using tracelogging::Guid::new() for the registration id.
    // That API uses UuidCreate() from RPCRT4.dll which is not available to enclaves.
    let registration_id = uuid::Uuid::new_v4();
    let uuid_prov_id = uuid::Uuid::from_fields(
        provider_id.data1,
        provider_id.data2,
        provider_id.data3,
        &provider_id.data4,
    );

    {
        let info = EtwProviderInfo {
            provider_id: uuid_prov_id,
            registration_id,
            callback: outer_callback,
            callback_context: outer_context,
        };
        let mut map = etw_registration_map().write();
        map.table.insert(registration_id, info);
    }

    let enclave_info = match common::get_enclave_information() {
        Ok(info) => info,
        Err(_) => {
            // There is no accurate NTSTATUS mapping for HRESULT errors,
            // so return a generic error code.
            return 0x0000054F_u32; //ERROR_INTERNAL_ERROR
        }
    };

    let abi_result = untrusted::event_register(
        &uuid_to_abi(&uuid_prov_id),
        &uuid_to_abi(&registration_id),
        enclave_info.BaseAddress as u64, // So the host can identify the enclave
        reg_handle,
    );

    let result = result_from_abi(abi_result);
    if result != 0 {
        let mut map = etw_registration_map().write();
        map.table.remove(&registration_id);
    }

    result
}

/// Implementation of declared ETW SetInformation function called by the ETW framework.
/// See: https://github.com/microsoft/tracelogging/blob/rust1.2.4/etw/rust/tracelogging/src/native.rs#L475
#[unsafe(no_mangle)]
unsafe extern "system" fn EtwSetInformation(
    reg_handle: u64,
    information_class: u32,
    information: *const u8,
    information_length: u32,
) -> u32 {
    // Convert the raw pointer and length to a slice. This comes from the tracelogging
    // crate itself, so we assume it's valid. We're just forwarding it through the abi
    // layer.
    // See: https://github.com/microsoft/tracelogging/blob/rust1.2.4/etw/rust/tracelogging/src/provider.rs#L248
    // See: https://github.com/microsoft/tracelogging/blob/rust1.2.4/etw/rust/tracelogging/src/provider.rs#L34
    // The meta variable is a static slice that describes the event data.
    let info_slice =
        unsafe { core::slice::from_raw_parts(information, information_length as usize) };

    let result =
        untrusted::event_set_information(reg_handle, information_class, &info_slice.to_vec());

    result_from_abi(result)
}

/// Implementation of declared ETW WriteTransfer function called by the ETW framework.
/// See: https://github.com/microsoft/tracelogging/blob/rust1.2.4/etw/rust/tracelogging/src/native.rs#L481
#[unsafe(no_mangle)]
unsafe extern "system" fn EtwWriteTransfer(
    reg_handle: u64,
    descriptor: *const core::ffi::c_void,
    activity_id: Option<&[u8; 16]>,
    related_id: Option<&[u8; 16]>,
    data_count: u32,
    data: *const EventDataDescriptor,
) -> u32 {
    let activity_guid = if let Some(activity_id) = activity_id {
        let guid = uuid::Uuid::from_bytes_le(*activity_id);
        Some(uuid_to_abi(&guid))
    } else {
        None
    };

    let related_guid = if let Some(related_id) = related_id {
        let guid = uuid::Uuid::from_bytes_le(*related_id);
        Some(uuid_to_abi(&guid))
    } else {
        None
    };

    // Value comes directly from tracelogging crate to pass to the real win32 function.
    // So, it should be valid. We're just acting in the middle so we can pass it through
    // the abi layer to the host. We confirmed the layout of their EventDescriptor
    // matches ours since they both use repr(C).
    let descriptor = unsafe { &*(descriptor as *const EventDescriptor) };

    let abi_descriptor = edl_types::EventDescriptor {
        id: descriptor.id,
        version: descriptor.version,
        channel: descriptor.channel.as_int(),
        level: descriptor.level.as_int(),
        opcode: descriptor.opcode.as_int(),
        task: descriptor.task,
        keyword: descriptor.keyword,
    };

    // Value comes directly from tracelogging crate to pass to the real win32 function.
    // So, it should be valid. We're just acting in the middle so we can pass it through
    // the abi layer and to the host.
    let data_descriptor = unsafe { core::slice::from_raw_parts(data, data_count as usize) };

    let mut abi_data: Vec<edl_types::EventDataDescriptor> = Vec::with_capacity(data_count as usize);

    for desc in data_descriptor.iter() {
        // data comes from tracelogging crate, so it should be valid.
        // See: https://github.com/microsoft/tracelogging/blob/rust1.2.4/etw/rust/tracelogging/src/descriptors.rs#L120
        let data_slice =
            unsafe { core::slice::from_raw_parts(desc.ptr as *const u8, desc.size as usize) };

        abi_data.push(edl_types::EventDataDescriptor {
            descriptor: data_slice.to_vec(),
            reserved: desc.reserved,
        });
    }

    let result = untrusted::event_write_transfer(
        reg_handle,
        &abi_descriptor,
        &activity_guid,
        &related_guid,
        &abi_data.to_vec(),
    );

    result_from_abi(result)
}

/// Implementation of declared ETW ActivityIdControl function called by the ETW framework.
/// See: https://github.com/microsoft/tracelogging/blob/rust1.2.4/etw/rust/tracelogging/src/native.rs#L489
#[unsafe(no_mangle)]
unsafe extern "system" fn EtwActivityIdControl(
    control_code: u32,
    activity_id: &mut edl_types::Guid,
) -> u32 {
    let result = untrusted::event_activity_id_control(control_code, activity_id);
    result_from_abi(result)
}

pub fn etw_callback_passthrough(
    registration_id: &edl_types::Guid,
    source_id: &edl_types::Guid,
    event_control_code: u32,
    level: u8,
    match_any_keyword: u64,
    match_all_keyword: u64,
    filter_data: &edl_types::EventFilterDescriptor,
) -> Result<(), AbiError> {
    let reg_id = uuid::Uuid::from_fields(
        registration_id.data1,
        registration_id.data2,
        registration_id.data3,
        &registration_id.data4,
    );

    let map = etw_registration_map().read();
    let info: &EtwProviderInfo = map
        .table
        .get(&reg_id)
        .ok_or(AbiError::Win32Error(0x00000490))?; // ERROR_NOT_FOUND

    let filter_data = EventFilterDescriptor {
        ptr: filter_data.descriptor.as_ptr() as u64,
        size: filter_data.descriptor.len() as u32,
        Type: filter_data.type_data,
        lifetime: PhantomData,
    };

    // Call the etw frameworks original callback function that was passed during registration.
    // this will then call the developers callback they passed to provider.register_with_callback().
    // See: https://github.com/microsoft/tracelogging/blob/rust1.2.4/etw/rust/tracelogging/src/provider.rs#L217
    // The etw frameworks callback is guaranteed to be valid since it was passed during registration.
    (info.callback)(
        source_id,
        event_control_code,
        level.into(),
        match_any_keyword,
        match_all_keyword,
        &filter_data as *const EventFilterDescriptor as usize,
        info.callback_context,
    );

    Ok(())
}
