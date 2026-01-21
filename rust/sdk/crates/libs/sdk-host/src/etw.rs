// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::{OnceLock, RwLock};
use veil_abi_host_gen::AbiError;
use veil_abi_host_gen::export_interface;
use veil_abi_host_gen::implementation::types as codegen_types;
use veil_abi_host_gen::implementation::untrusted::Untrusted;
use windows::Win32::System::Diagnostics::Etw;

#[repr(C)]
pub struct EtwProviderContext {
    provider_id: codegen_types::Guid,
    registration_id: codegen_types::Guid,
    enclave: u64,
}

#[derive(Default)]
pub struct EtwContextList {
    list: Vec<EtwProviderContext>,
}

static ETW_CONTEXT_LIST: OnceLock<RwLock<EtwContextList>> = OnceLock::new();

pub fn etw_context_list() -> &'static RwLock<EtwContextList> {
    ETW_CONTEXT_LIST.get_or_init(|| RwLock::new(EtwContextList::default()))
}

fn winguid_to_abi_guid(guid: &windows::core::GUID) -> codegen_types::Guid {
    codegen_types::Guid {
        data1: guid.data1,
        data2: guid.data2,
        data3: guid.data3,
        data4: guid.data4,
    }
}

fn abi_guid_to_winguid(guid: &codegen_types::Guid) -> windows::core::GUID {
    windows::core::GUID::from_values(guid.data1, guid.data2, guid.data3, guid.data4)
}

// This is the callback function that will be called by the ETW framework when
// an enablement/disablement event is triggered. We will forward the contents
// of this callback into the enclave and invoke the users original callback function
// there.
#[unsafe(no_mangle)]
unsafe extern "system" fn etw_call_back(
    source_id: *const windows::core::GUID,
    is_enabled: Etw::ENABLECALLBACK_ENABLED_STATE,
    level: u8,
    match_any_keyword: u64,
    match_all_keyword: u64,
    filter_data: *const Etw::EVENT_FILTER_DESCRIPTOR,
    callback_context: *mut core::ffi::c_void,
) {
    if source_id.is_null() {
        // This comes from the etw framework. It should never happen. If it does, we cannot proceed.
        // Etw is best-effort delivery, so we will just return.
        return;
    }

    if callback_context.is_null() {
        // This comes from the etw framework. It should never happen. If it does, we cannot proceed.
        // Etw is best-effort delivery, so we will just return.
        return;
    }

    // The callback from the Etw framework does not manipulate the context that we originally passed in.
    // It simply passes it back to us. So, we can safely cast it back to our EtwProviderContext object.
    // We have to use unsafe because we're dereferencing a raw pointer in rust.
    let context = unsafe { &*(callback_context as *const EtwProviderContext) };

    // At this point edlcodegen callback infrastructure is already registered. So, we can create
    // the interface to call the etw passthrough callback.
    let interface = export_interface::new(context.enclave as *mut core::ffi::c_void);

    // Windows guid pointer comes from the Etw Framework. It is expected to be valid. We have to use unsafe because
    // we're dereferencing a raw pointer in rust.
    let win_guid = unsafe { &*(source_id) };
    let abi_source_guid = winguid_to_abi_guid(win_guid);

    let mut abi_filter_descriptor = codegen_types::EventFilterDescriptor {
        descriptor: Vec::new(),
        type_data: 0,
    };

    if !filter_data.is_null() {
        // Windows filter data pointer comes from the Etw Framework. It is expected to be valid.
        // We have to use unsafe because we're dereferencing a raw pointer in rust.
        let win_filter_data = unsafe { &*(filter_data) };
        let filter_slice = unsafe {
            std::slice::from_raw_parts(
                win_filter_data.Ptr as *const u8,
                win_filter_data.Size as usize,
            )
        };

        abi_filter_descriptor.descriptor = filter_slice.to_vec();
        abi_filter_descriptor.type_data = win_filter_data.Type;
    }

    // send callback data back to enclave
    let _ = interface.etw_callback_passthrough(
        &context.registration_id,
        &abi_source_guid,
        is_enabled.0,
        level,
        match_any_keyword,
        match_all_keyword,
        &abi_filter_descriptor,
    );
}

pub struct HostImpl {}

impl Untrusted for HostImpl {
    fn event_unregister(reg_handle: u64) -> Result<u32, AbiError> {
        let result = unsafe { Etw::EventUnregister(Etw::REGHANDLE(reg_handle as i64)) };
        Ok(result)
    }

    fn event_register(
        provider_id: &codegen_types::Guid,
        registration_id: &codegen_types::Guid,
        enclave: u64,
        reg_handle: &mut u64,
    ) -> Result<u32, AbiError> {
        let guid = abi_guid_to_winguid(provider_id);

        let mut etw_context = etw_context_list()
            .write()
            .expect("Failed to acquire ETW context list write lock");

        etw_context.list.push(EtwProviderContext {
            provider_id: provider_id.clone(),
            registration_id: registration_id.clone(),
            enclave,
        });

        let context_entry = etw_context.list.last().unwrap();
        let last_entry_pvoid = context_entry as *const _ as *const core::ffi::c_void;

        let result = unsafe {
            let mut handle = Etw::REGHANDLE(0);
            let res_code = Etw::EventRegister(
                &guid,
                Some(etw_call_back),
                Some(last_entry_pvoid),
                &mut handle,
            );

            *reg_handle = handle.0 as u64;
            res_code
        };

        Ok(result)
    }

    fn event_write_transfer(
        reg_handle: u64,
        descriptor: &codegen_types::EventDescriptor,
        activity_id: &Option<codegen_types::Guid>,
        related_id: &Option<codegen_types::Guid>,
        user_data: &Vec<codegen_types::EventDataDescriptor>,
    ) -> Result<u32, AbiError> {
        let etw_descriptor = Etw::EVENT_DESCRIPTOR {
            Id: descriptor.id,
            Version: descriptor.version,
            Channel: descriptor.channel,
            Level: descriptor.level,
            Opcode: descriptor.opcode,
            Task: descriptor.task,
            Keyword: descriptor.keyword,
        };

        let etw_activity_id = match activity_id {
            Some(guid) => {
                let win_guid = abi_guid_to_winguid(guid);
                Some(&win_guid as *const windows::core::GUID)
            }
            None => None,
        };

        let etw_related_id = match related_id {
            Some(guid) => {
                let win_guid = abi_guid_to_winguid(guid);
                Some(&win_guid as *const windows::core::GUID)
            }
            None => None,
        };

        let mut descriptors: Vec<Etw::EVENT_DATA_DESCRIPTOR> = Vec::with_capacity(user_data.len());
        for desc in user_data.iter() {
            descriptors.push(Etw::EVENT_DATA_DESCRIPTOR {
                Ptr: desc.descriptor.as_ptr() as u64,
                Size: desc.descriptor.len() as u32,
                Anonymous: Etw::EVENT_DATA_DESCRIPTOR_0 {
                    Reserved: desc.reserved,
                },
            });
        }

        let mut op_descriptor: Option<&[Etw::EVENT_DATA_DESCRIPTOR]> = None;
        if !descriptors.is_empty() {
            op_descriptor = Some(descriptors.as_slice());
        }

        let result = unsafe {
            Etw::EventWriteTransfer(
                Etw::REGHANDLE(reg_handle as i64),
                &etw_descriptor,
                etw_activity_id,
                etw_related_id,
                op_descriptor,
            )
        };

        Ok(result)
    }

    fn event_set_information(
        reg_handle: u64,
        information_class: u32,
        information: &Vec<u8>,
    ) -> Result<u32, AbiError> {
        let info_class = Etw::EVENT_INFO_CLASS(information_class as i32);
        let result = unsafe {
            Etw::EventSetInformation(
                Etw::REGHANDLE(reg_handle as i64),
                info_class,
                information.as_ptr() as *const core::ffi::c_void,
                information.len() as u32,
            )
        };

        Ok(result)
    }

    fn event_activity_id_control(
        control_code: u32,
        activity_id: &mut codegen_types::Guid,
    ) -> Result<u32, AbiError> {
        let mut win_guid = abi_guid_to_winguid(activity_id);
        let result = unsafe { Etw::EventActivityIdControl(control_code, &mut win_guid) };

        *activity_id = winguid_to_abi_guid(&win_guid);
        Ok(result)
    }
}
