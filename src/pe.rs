//! Minimal PE import reader: the DLLs a binary asks the loader for. The panel
//! uses it to tell "a library is missing" apart from a port or configuration
//! problem, before the user starts reading the event viewer.

use std::fs;
use std::path::Path;

fn u16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

/// Direct imports of `path`; empty when the file is not a PE image.
pub fn imports(path: &Path) -> Vec<String> {
    let d = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    if d.len() < 0x40 || &d[..2] != b"MZ" {
        return Vec::new();
    }
    let lf = u32(&d, 0x3C) as usize;
    if lf + 24 >= d.len() || &d[lf..lf + 4] != b"PE\0\0" {
        return Vec::new();
    }
    let nsec = u16(&d, lf + 6) as usize;
    let sizeopt = u16(&d, lf + 20) as usize;
    let opt = lf + 24;
    let pe64 = u16(&d, opt) == 0x20B;
    let diroff = opt + if pe64 { 112 } else { 96 };
    if diroff + 16 > d.len() {
        return Vec::new();
    }
    let (imp_rva, _) = (u32(&d, diroff + 8), u32(&d, diroff + 12));
    let secoff = opt + sizeopt;
    let mut secs: Vec<(usize, usize, usize, usize)> = Vec::new();
    for i in 0..nsec {
        let o = secoff + i * 40;
        if o + 40 > d.len() {
            break;
        }
        secs.push((
            u32(&d, o + 12) as usize,
            u32(&d, o + 8) as usize,
            u32(&d, o + 20) as usize,
            u32(&d, o + 16) as usize,
        ));
    }
    let r2o = |rva: usize| -> Option<usize> {
        for &(va, vsz, rawptr, rawsz) in secs.iter() {
            if rva >= va && rva < va + vsz.max(rawsz) {
                let o = rawptr + (rva - va);
                if o < d.len() {
                    return Some(o);
                }
            }
        }
        None
    };
    let mut out: Vec<String> = Vec::new();
    let mut o = match r2o(imp_rva as usize) {
        Some(o) => o,
        None => return out,
    };
    for _ in 0..256 {
        if o + 20 > d.len() {
            break;
        }
        let ilt = u32(&d, o);
        let name_rva = u32(&d, o + 12);
        let thunk = u32(&d, o + 16);
        if name_rva == 0 && ilt == 0 && thunk == 0 {
            break;
        }
        if let Some(no) = r2o(name_rva as usize) {
            let mut e = no;
            while e < d.len() && d[e] != 0 {
                e += 1;
            }
            let name = String::from_utf8_lossy(&d[no..e]).into_owned();
            if !name.is_empty() {
                out.push(name);
            }
        }
        o += 20;
    }
    out
}
