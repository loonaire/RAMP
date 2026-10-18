//! Minimal HTTPS client built on WinHTTP: no extra crates, TLS comes from
//! Schannel, system proxy settings are honoured (WINHTTP_ACCESS_TYPE_DEFAULT_PROXY).

use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Networking::WinHttp::*;

pub fn widez(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

const UA: &str = "xampp-rs-updater/1.0";

pub struct Resp {
    pub status: u16,
    pub body: Vec<u8>,
}

struct Conn {
    session: *mut c_void,
    conn: *mut c_void,
    req: *mut c_void,
}

// Closing a connection handle invalidates every request handle built from it, so
// all three handles stay alive until the response has been read.
impl Drop for Conn {
    fn drop(&mut self) {
        unsafe {
            if !self.req.is_null() {
                let _ = WinHttpCloseHandle(self.req);
            }
            if !self.conn.is_null() {
                let _ = WinHttpCloseHandle(self.conn);
            }
            if !self.session.is_null() {
                let _ = WinHttpCloseHandle(self.session);
            }
        }
    }
}

fn split(url: &str) -> Result<(u16, String, String), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("bad URL: {url}"))?;
    match scheme {
        "https" => {}
        s => return Err(format!("HTTPS required, refused: {s}")),
    }
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| format!("bad port: {p}"))?,
        ),
        None => (hostport.to_string(), 443u16),
    };
    Ok((port, host, path))
}

fn open_request(url: &str) -> Result<Conn, String> {
    let (port, host, path) = split(url)?;
    let agent = widez(UA);
    let session = unsafe {
        WinHttpOpen(
            PCWSTR(agent.as_ptr()),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        )
    };
    if session.is_null() {
        return Err("WinHttpOpen failed".into());
    }
    let mut guard = Conn {
        session,
        conn: std::ptr::null_mut(),
        req: std::ptr::null_mut(),
    };
    unsafe {
        let _ = WinHttpSetTimeouts(guard.session, 15_000, 25_000, 60_000, 120_000);
        let policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS.to_le_bytes();
        WinHttpSetOption(
            Some(guard.session),
            WINHTTP_OPTION_REDIRECT_POLICY,
            Some(&policy),
        )
        .map_err(|e| format!("option redirect: {e}"))?;

        let hostw = widez(&host);
        let server = WinHttpConnect(guard.session, PCWSTR(hostw.as_ptr()), port, 0);
        if server.is_null() {
            return Err(format!("WinHttpConnect({host}) failed"));
        }
        guard.conn = server;
        let pathw = widez(&path);
        let req = WinHttpOpenRequest(
            server,
            PCWSTR(widez("GET").as_ptr()),
            PCWSTR(pathw.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        );
        if req.is_null() {
            return Err(format!("WinHttpOpenRequest({host}{path}) failed"));
        }
        let hdrs: Vec<u16> =
            format!("User-Agent: {UA}\r\nAccept: */*\r\nAccept-Encoding: identity\r\n")
                .encode_utf16()
                .collect();
        let _ = WinHttpAddRequestHeaders(req, &hdrs, WINHTTP_ADDREQ_FLAG_ADD);
        guard.req = req;
        Ok(guard)
    }
}

fn status_of(req: *mut c_void) -> Result<u16, String> {
    let mut code: u32 = 0;
    let mut len = 4u32;
    unsafe {
        WinHttpQueryHeaders(
            req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut code as *mut u32 as *mut c_void),
            &mut len,
            std::ptr::null_mut(),
        )
        .map_err(|e| format!("read status: {e}"))?;
    }
    Ok(code as u16)
}

fn content_length(req: *mut c_void) -> u64 {
    let mut len: u32 = 0;
    let mut buflen = 4u32;
    unsafe {
        match WinHttpQueryHeaders(
            req,
            WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut len as *mut u32 as *mut c_void),
            &mut buflen,
            std::ptr::null_mut(),
        ) {
            Ok(()) => u64::from(len),
            Err(_) => 0,
        }
    }
}

/// Body of one GET. Redirects are followed by WinHTTP itself.
pub fn http_get(url: &str) -> Result<Resp, String> {
    let conn = open_request(url)?;
    unsafe {
        WinHttpSendRequest(conn.req, None, None, 0, 0, 0)
            .map_err(|e| format!("send to {}: {e}", redact(url)))?;
        WinHttpReceiveResponse(conn.req, std::ptr::null_mut())
            .map_err(|e| format!("reply from {}: {e}", redact(url)))?;
        let status = status_of(conn.req)?;
        let mut body: Vec<u8> = Vec::new();
        loop {
            let mut avail: u32 = 0;
            WinHttpQueryDataAvailable(conn.req, &mut avail).map_err(|e| format!("dispo: {e}"))?;
            if avail == 0 {
                break;
            }
            let n = avail.min(64 * 1024);
            let mut buf = vec![0u8; n as usize];
            let mut got: u32 = 0;
            WinHttpReadData(conn.req, buf.as_mut_ptr() as *mut c_void, n, &mut got)
                .map_err(|e| format!("read: {e}"))?;
            if got == 0 {
                break;
            }
            body.extend_from_slice(&buf[..got as usize]);
        }
        Ok(Resp { status, body })
    }
}

pub fn http_get_text(url: &str) -> Result<String, String> {
    let r = http_get(url)?;
    if r.status != 200 {
        return Err(format!("HTTP {} from {}", r.status, redact(url)));
    }
    Ok(String::from_utf8_lossy(&r.body).into_owned())
}

/// Streamed download to `dest`; `progress(done, total)` where total = 0 is unknown.
pub fn http_download(
    url: &str,
    dest: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<u64, String> {
    let conn = open_request(url)?;
    unsafe {
        WinHttpSendRequest(conn.req, None, None, 0, 0, 0)
            .map_err(|e| format!("send to {}: {e}", redact(url)))?;
        WinHttpReceiveResponse(conn.req, std::ptr::null_mut())
            .map_err(|e| format!("reply from {}: {e}", redact(url)))?;
        let status = status_of(conn.req)?;
        if status != 200 {
            return Err(format!("HTTP {} from {}", status, redact(url)));
        }
        let total = content_length(conn.req);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let mut file = File::create(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
        let mut done: u64 = 0;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let mut avail: u32 = 0;
            WinHttpQueryDataAvailable(conn.req, &mut avail).map_err(|e| format!("dispo: {e}"))?;
            if avail == 0 {
                break;
            }
            let n = avail.min(buf.len() as u32);
            let mut got: u32 = 0;
            WinHttpReadData(conn.req, buf.as_mut_ptr() as *mut c_void, n, &mut got)
                .map_err(|e| format!("read: {e}"))?;
            if got == 0 {
                break;
            }
            file.write_all(&buf[..got as usize])
                .map_err(|e| format!("write {}: {e}", dest.display()))?;
            done += u64::from(got);
            if done % (256 * 1024) < u64::from(got) {
                progress(done, total);
            }
        }
        file.flush().map_err(|e| format!("flush: {e}"))?;
        if total > 0 && done != total {
            return Err(format!("truncated download: {done}/{total} bytes"));
        }
        progress(done, total.max(done));
        Ok(done)
    }
}

/// URLs can carry a signed SourceForge token; keep logs clean.
fn redact(url: &str) -> String {
    match url.split_once('?') {
        Some((base, _)) => format!("{base}?…"),
        None => url.to_string(),
    }
}
