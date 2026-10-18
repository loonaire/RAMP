use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Clone)]
pub struct TcpEntry {
    pub local: u16,
    pub pid: u32,
}

fn swap_port(p: u32) -> u16 {
    (((p & 0xFF00) >> 8) | ((p & 0xFF) << 8)) as u16
}

/// Owner-pid TCP table. MariaDB binds to "::" unless my.ini pins a
/// bind-address, so the IPv6 table alone often holds the only listener.
pub fn tcp_table() -> Vec<TcpEntry> {
    let mut out = tcp_table_family(AF_INET.0 as u32);
    out.extend(tcp_table_family(AF_INET6.0 as u32));
    out
}

fn tcp_table_family(af: u32) -> Vec<TcpEntry> {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(None, &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
        let mut buf: Vec<u8> = vec![0; size as usize + 512];
        let mut err = WIN32_ERROR(0);
        for _ in 0..10 {
            let mut sz = buf.len() as u32;
            err = WIN32_ERROR(GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut sz,
                false,
                af,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ));
            if err == ERROR_INSUFFICIENT_BUFFER {
                buf.resize(sz as usize + 512, 0);
                continue;
            }
            break;
        }
        if err.0 != 0 || buf.is_empty() {
            return Vec::new();
        }
        if af == AF_INET6.0 as u32 {
            if buf.len() < std::mem::size_of::<MIB_TCP6TABLE_OWNER_PID>() {
                return Vec::new();
            }
            let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let count = table.dwNumEntries as usize;
            if count == 0 {
                return Vec::new();
            }
            let rows =
                std::slice::from_raw_parts(&table.table[0] as *const MIB_TCP6ROW_OWNER_PID, count);
            rows.iter()
                .map(|row| TcpEntry {
                    local: swap_port(row.dwLocalPort),
                    pid: row.dwOwningPid,
                })
                .collect()
        } else {
            if buf.len() < std::mem::size_of::<MIB_TCPTABLE_OWNER_PID>() {
                return Vec::new();
            }
            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let count = table.dwNumEntries as usize;
            if count == 0 {
                return Vec::new();
            }
            let rows =
                std::slice::from_raw_parts(&table.table[0] as *const MIB_TCPROW_OWNER_PID, count);
            rows.iter()
                .map(|row| TcpEntry {
                    local: swap_port(row.dwLocalPort),
                    pid: row.dwOwningPid,
                })
                .collect()
        }
    }
}

pub fn ports_for_pid(entries: &[TcpEntry], pid: u32) -> Vec<u16> {
    let mut ports: Vec<u16> = entries
        .iter()
        .filter(|e| e.pid == pid)
        .map(|e| e.local)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub fn pid_on_port(entries: &[TcpEntry], port: u16) -> Option<u32> {
    entries.iter().find(|e| e.local == port).map(|e| e.pid)
}
