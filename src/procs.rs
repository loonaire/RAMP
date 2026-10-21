use std::path::Path;

use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub struct ProcEntry {
    pub pid: u32,
    pub name: String,
}

pub fn list_processes() -> Vec<ProcEntry> {
    let mut out = Vec::new();
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return out,
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                out.push(ProcEntry {
                    pid: entry.th32ProcessID,
                    name: String::from_utf16_lossy(&entry.szExeFile[..len]),
                });
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

pub fn process_path(pid: u32) -> String {
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return String::new(),
        };
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let result = QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(h);
        match result {
            Ok(()) => String::from_utf16_lossy(&buf[..size as usize]),
            Err(_) => String::new(),
        }
    }
}

/// True when the executable `path` lies inside the `root` tree (case-insensitive,
/// either slash). A substring test would take C:\ramp-old for C:\ramp.
pub fn path_in_tree(root: &Path, path: &str) -> bool {
    let root = root.to_string_lossy().replace('/', "\\").to_lowercase();
    let root = root.trim_end_matches('\\');
    let path = path.replace('/', "\\").to_lowercase();
    !root.is_empty()
        && path.len() > root.len()
        && path.starts_with(root)
        && path.as_bytes()[root.len()] == b'\\'
}

/// True when process `pid` runs an executable from the `root` tree: only those
/// belong to this installation and may be stopped by the panel.
pub fn pid_in_tree(root: &Path, pid: u32) -> bool {
    pid != 0 && path_in_tree(root, &process_path(pid))
}

pub fn process_name_map() -> std::collections::HashMap<u32, String> {
    list_processes()
        .into_iter()
        .map(|p| (p.pid, p.name))
        .collect()
}
