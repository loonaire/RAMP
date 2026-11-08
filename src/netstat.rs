use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Clone)]
pub struct TcpEntry {
    pub local: u16,
    /// 0 for a listener: it has no peer.
    pub remote: u16,
    pub pid: u32,
    /// MIB_TCP_STATE_* value; not to be trusted alone, see listening().
    pub state: u32,
}

/// MIB_TCP_STATE_LISTEN.
const LISTEN: u32 = 2;

impl TcpEntry {
    /// A server socket. Every other row is a connection: a client being served
    /// (its local port is the listening one anyway), a closing one, or one the
    /// server opened itself, such as PHP inside httpd talking to MariaDB, whose
    /// local port is a random ephemeral one.
    ///
    /// The state alone is not enough: Windows 11 build 26300 reports listening
    /// sockets with a state of 0 or 1 instead of MIB_TCP_STATE_LISTEN (netstat
    /// itself stops printing them). A listener is also the only row without a
    /// peer, and a connection always has a remote port, so either sign counts.
    pub fn listening(&self) -> bool {
        self.state == LISTEN || self.remote == 0
    }
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
                    remote: swap_port(row.dwRemotePort),
                    pid: row.dwOwningPid,
                    state: row.dwState,
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
                    remote: swap_port(row.dwRemotePort),
                    pid: row.dwOwningPid,
                    state: row.dwState,
                })
                .collect()
        }
    }
}

/// The ports a process serves on: its listening sockets only, so the ports of
/// its live connections never show up in the PORT(S) column.
pub fn ports_for_pid(entries: &[TcpEntry], pid: u32) -> Vec<u16> {
    let mut ports: Vec<u16> = entries
        .iter()
        .filter(|e| e.pid == pid && e.listening())
        .map(|e| e.local)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The process listening on `port`; a connection that merely uses that port
/// number does not keep a server from binding it.
pub fn pid_on_port(entries: &[TcpEntry], port: u16) -> Option<u32> {
    entries
        .iter()
        .find(|e| e.local == port && e.listening())
        .map(|e| e.pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOSED: u32 = 1;
    const ESTABLISHED: u32 = 5;
    const TIME_WAIT: u32 = 11;

    fn row(local: u16, remote: u16, pid: u32, state: u32) -> TcpEntry {
        TcpEntry { local, remote, pid, state }
    }

    #[test]
    fn only_listening_sockets_are_server_ports() {
        let table = [
            row(80, 0, 10, LISTEN),
            // Listeners as Windows 11 build 26300 reports them.
            row(443, 0, 10, 0),
            row(8443, 0, 10, CLOSED),
            // A browser being served: same local port as the listener.
            row(80, 56616, 10, ESTABLISHED),
            // PHP inside httpd connected to MariaDB, then a closed request.
            row(52341, 3306, 10, ESTABLISHED),
            row(52342, 3306, 10, TIME_WAIT),
            row(3306, 0, 20, 0),
        ];
        assert_eq!(ports_for_pid(&table, 10), vec![80, 443, 8443]);
        assert_eq!(ports_for_pid(&table, 20), vec![3306]);
        assert_eq!(pid_on_port(&table, 3306), Some(20));
        assert_eq!(pid_on_port(&table, 52341), None);
    }

    /// Against the real TCP table of this machine: a listener of this process
    /// must be found, the client connection made to it must not.
    #[test]
    fn live_listener_is_found_and_its_connections_are_not() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (_served, _) = listener.accept().unwrap();
        let ephemeral = client.local_addr().unwrap().port();
        let table = tcp_table();
        let me = std::process::id();
        let ports = ports_for_pid(&table, me);
        assert!(ports.contains(&port), "listener {port} missing from {ports:?}");
        assert!(!ports.contains(&ephemeral), "client port {ephemeral} listed in {ports:?}");
        assert_eq!(pid_on_port(&table, port), Some(me));

        // Apache and MariaDB may listen on "::" too; skipped where IPv6 is off.
        if let Ok(v6) = std::net::TcpListener::bind("[::]:0") {
            let port6 = v6.local_addr().unwrap().port();
            let ports = ports_for_pid(&tcp_table(), me);
            assert!(ports.contains(&port6), "IPv6 listener {port6} missing from {ports:?}");
        }
    }
}
