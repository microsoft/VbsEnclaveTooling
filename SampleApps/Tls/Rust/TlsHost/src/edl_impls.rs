// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side (VTL0) implementation of the untrusted EDL surface: TCP transport
//! callbacks over blocking sockets. The enclave drives the whole exchange to
//! completion, so these callbacks simply block until each I/O completes.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Mutex, OnceLock};

use tls_sample_host_gen::implementation::types::*;
use tls_sample_host_gen::implementation::untrusted::Untrusted;
use tls_sample_host_gen::AbiError;

struct SocketTable {
    next_handle: u64,
    sockets: HashMap<u64, TcpStream>,
}

fn socket_table() -> &'static Mutex<SocketTable> {
    static TABLE: OnceLock<Mutex<SocketTable>> = OnceLock::new();
    TABLE.get_or_init(|| {
        Mutex::new(SocketTable {
            next_handle: 1,
            sockets: HashMap::new(),
        })
    })
}

pub struct HostImpl;

impl Untrusted for HostImpl {
    fn TlsSample_HostTcpConnect(
        server_name: &str,
        server_port: u16,
    ) -> Result<HostTcpConnectResult, AbiError> {
        let mut result = HostTcpConnectResult::default();
        match TcpStream::connect((server_name, server_port)) {
            Ok(stream) => {
                let mut table = socket_table().lock().unwrap();
                let handle = table.next_handle;
                table.next_handle += 1;
                table.sockets.insert(handle, stream);
                result.status = HostIoStatus::HostIoStatus_Ok;
                result.transport_handle = handle;
            }
            Err(_) => {
                result.status = HostIoStatus::HostIoStatus_Failed;
            }
        }
        Ok(result)
    }

    fn TlsSample_HostTcpRecv(
        transport_handle: u64,
        max_bytes: u32,
    ) -> Result<HostTcpRecvResult, AbiError> {
        let mut result = HostTcpRecvResult::default();
        let mut table = socket_table().lock().unwrap();
        let Some(stream) = table.sockets.get_mut(&transport_handle) else {
            result.status = HostIoStatus::HostIoStatus_Failed;
            return Ok(result);
        };

        let mut buffer = vec![0u8; max_bytes as usize];
        match stream.read(&mut buffer) {
            Ok(0) => result.status = HostIoStatus::HostIoStatus_Closed,
            Ok(n) => {
                buffer.truncate(n);
                result.bytes = buffer;
                result.status = HostIoStatus::HostIoStatus_Ok;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                result.status = HostIoStatus::HostIoStatus_WouldBlock;
            }
            Err(_) => result.status = HostIoStatus::HostIoStatus_Failed,
        }
        Ok(result)
    }

    fn TlsSample_HostTcpSend(
        transport_handle: u64,
        bytes: &[u8],
    ) -> Result<HostIoResult, AbiError> {
        let mut result = HostIoResult::default();
        let mut table = socket_table().lock().unwrap();
        let Some(stream) = table.sockets.get_mut(&transport_handle) else {
            result.status = HostIoStatus::HostIoStatus_Failed;
            return Ok(result);
        };

        match stream.write(bytes) {
            Ok(n) => {
                result.status = HostIoStatus::HostIoStatus_Ok;
                result.bytes_transferred = n as u32;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                result.status = HostIoStatus::HostIoStatus_WouldBlock;
            }
            Err(_) => result.status = HostIoStatus::HostIoStatus_Failed,
        }
        Ok(result)
    }

    fn TlsSample_HostTcpClose(transport_handle: u64) -> Result<HostIoResult, AbiError> {
        let mut result = HostIoResult::default();
        let mut table = socket_table().lock().unwrap();
        table.sockets.remove(&transport_handle);
        result.status = HostIoStatus::HostIoStatus_Ok;
        Ok(result)
    }
}
