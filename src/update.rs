//! Manual updater for the bundled stacks: Apache (Apache Lounge build), MariaDB,
//! PHP and phpMyAdmin, straight from their upstream feeds.
//!
//! Everything file-system related runs off the UI thread; the UI thread owns
//! start/stop of the modules (it owns `App` ).

use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
};

use crate::http;

// ---------------------------------------------------------------- components

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Comp {
    Apache = 0,
    Mysql = 1,
    Php = 2,
    Phpmyadmin = 3,
}

impl Comp {
    pub fn all() -> [Comp; 4] {
        [Comp::Apache, Comp::Mysql, Comp::Php, Comp::Phpmyadmin]
    }
    pub fn label(self) -> &'static str {
        match self {
            Comp::Apache => "Apache",
            Comp::Mysql => "MariaDB",
            Comp::Php => "PHP",
            Comp::Phpmyadmin => "phpMyAdmin",
        }
    }
    /// Directory under basedir that gets replaced.
    pub fn dir(self) -> &'static str {
        match self {
            Comp::Apache => "apache",
            Comp::Mysql => "mysql",
            Comp::Php => "php",
            Comp::Phpmyadmin => "phpMyAdmin",
        }
    }
    /// Entry point inside that directory, used for the PE version and checks.
    pub fn exe(self) -> &'static str {
        match self {
            Comp::Apache => "bin/httpd.exe",
            Comp::Mysql => "bin/mysqld.exe",
            Comp::Php => "php.exe",
            // phpMyAdmin is a PHP app: no daemon, index.php is just the marker
            // used to locate the archive root.
            Comp::Phpmyadmin => "index.php",
        }
    }
    /// Every server-binary name this component is known to ship, preferred first.
    /// MariaDB renamed mysqld.exe to mariadbd.exe in 10.5, so a major jump can
    /// change the name the control panel has to start.
    pub fn exe_candidates(self) -> &'static [&'static str] {
        match self {
            Comp::Apache => &["bin/httpd.exe"],
            Comp::Mysql => &["bin/mariadbd.exe", "bin/mysqld.exe"],
            Comp::Php => &["php.exe"],
            Comp::Phpmyadmin => &["index.php"],
        }
    }
    /// Module rows that must be stopped before swapping this component.
    pub fn modules(self) -> &'static [usize] {
        match self {
            Comp::Apache | Comp::Php | Comp::Phpmyadmin => &[0],
            Comp::Mysql => &[1],
        }
    }
}

// ------------------------------------------------------------------ versions

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ver(pub [u32; 4]);

impl Ver {
    pub fn parse(s: &str) -> Option<Ver> {
        let mut parts = [0u32; 4];
        let mut n = 0;
        for tok in s.split('.') {
            let digits: String = tok.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                break;
            }
            parts[n] = digits.parse().ok()?;
            n += 1;
            if n == 4 {
                break;
            }
        }
        if n == 0 {
            None
        } else {
            Some(Ver(parts))
        }
    }
    pub fn same_line(&self, other: &Ver) -> bool {
        self.0[0] == other.0[0] && self.0[1] == other.0[1]
    }
    pub fn show(&self) -> String {
        format!("{}.{}.{}", self.0[0], self.0[1], self.0[2])
    }
    /// File version resource says 0.0.0.0 when the exe has no version info.
    pub fn is_null(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }
}

fn ver_cmp(a: &Ver, b: &Ver) -> std::cmp::Ordering {
    a.0.cmp(&b.0)
}

/// File version of a PE binary (no process spawn, works while it is running ).
pub fn pe_version(path: &Path) -> Option<Ver> {
    let wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let size = GetFileVersionInfoSizeW(windows::core::PCWSTR(wide.as_ptr()), None);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        GetFileVersionInfoW(
            windows::core::PCWSTR(wide.as_ptr()),
            None,
            size,
            buf.as_mut_ptr() as *mut c_void,
        )
        .ok()?;
        let sub: Vec<u16> = vec![0x005Cu16, 0];
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        if !VerQueryValueW(
            buf.as_ptr() as *const c_void,
            windows::core::PCWSTR(sub.as_ptr()),
            &mut ptr,
            &mut len,
        )
        .as_bool()
        {
            return None;
        }
        if ptr.is_null() || (len as usize) < std::mem::size_of::<VS_FIXEDFILEINFO>() {
            return None;
        }
        let ffi: VS_FIXEDFILEINFO = std::ptr::read(ptr as *const VS_FIXEDFILEINFO);
        if ffi.dwSignature != 0xFEEF_04BD {
            return None;
        }
        Some(Ver([
            ffi.dwFileVersionMS >> 16,
            ffi.dwFileVersionMS & 0xFFFF,
            ffi.dwFileVersionLS >> 16,
            ffi.dwFileVersionLS & 0xFFFF,
        ]))
    }
}

/// Locate the server binary inside a component tree ("", forward slashes).
pub fn find_exe(root: &Path, comp: Comp) -> Option<&'static str> {
    comp.exe_candidates()
        .iter()
        .copied()
        .find(|c| root.join(c).is_file())
}

pub fn installed_version(basedir: &Path, comp: Comp) -> Result<Ver, String> {
    let dir = basedir.join(comp.dir());
    if comp == Comp::Phpmyadmin {
        return pma_release_date(&dir).ok_or_else(|| {
            format!("no RELEASE-DATE-x.y.z marker in {}", dir.display())
        });
    }
    let p = dir.join(find_exe(&dir, comp).unwrap_or(comp.exe()));
    match pe_version(&p) {
        Some(v) if !v.is_null() => Ok(v),
        _ => Err(format!("no version readable at {}", p.display())),
    }
}

/// phpMyAdmin trees carry a `RELEASE-DATE-5.2.1` marker file; both the installed
/// tree and the downloaded archive do, so it doubles as version and integrity hint.
fn pma_release_date(dir: &Path) -> Option<Ver> {
    let rd = fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if let Some(v) = name.strip_prefix("RELEASE-DATE-") {
            if let Some(ver) = Ver::parse(v) {
                return Some(ver);
            }
        }
    }
    None
}

// --------------------------------------------------------------------- feeds

#[derive(Clone, Debug)]
pub struct Info {
    pub comp: Comp,
    pub installed: String,
    pub available: String,
    pub url: String,
    pub file: String,
    pub sha256: String,
    pub size: u64,
    pub note: String,
    pub line: String,
    pub status: String,
}

const PHP_JSON: &str = "https://windows.php.net/downloads/releases/releases.json";
const PHP_STATES: &str = "https://www.php.net/releases/states.php";
const PHP_BASE: &str = "https://windows.php.net/downloads/releases";
const AL_PAGE: &str = "https://www.apachelounge.com/download/VS17/";
const AL_BASE: &str = "https://www.apachelounge.com/download/VS17/binaries";
const MDB_API: &str = "https://downloads.mariadb.org/rest-api/mariadb";
const PMA_API: &str = "https://api.github.com/repos/phpmyadmin/phpmyadmin/releases?per_page=60";
const PMA_BASE: &str = "https://files.phpmyadmin.net/phpMyAdmin";

fn human_size(s: &str) -> u64 {
    let s = s.trim().to_uppercase();
    let (num, mult) = if let Some(v) = s.strip_suffix("GB") {
        (v, 1_000_000_000.0)
    } else if let Some(v) = s.strip_suffix("MB") {
        (v, 1_000_000.0)
    } else if let Some(v) = s.strip_suffix("KB") {
        (v, 1_000.0)
    } else {
        (s.as_str(), 1.0)
    };
    num.trim()
        .replace(',', ".")
        .parse::<f64>()
        .map(|v| (v * mult) as u64)
        .unwrap_or(0)
}

pub fn installed_opt(basedir: &Path, comp: Comp) -> Option<Ver> {
    installed_version(basedir, comp).ok()
}

/// Support state of one PHP branch, as php.net publishes it.
struct PhpBranch {
    /// "stable" (active support), "security" (security fixes only) or "eol".
    state: String,
    active_end: String,
    security_end: String,
}

/// php.net's releases/states.php: `{"8": {"8.4": {"state": "stable",
/// "active_support_end": "2026-12-31T00:00:00+00:00", ...}}}`, keyed "8.4".
fn parse_php_states(txt: &str) -> Result<std::collections::HashMap<String, PhpBranch>, String> {
    let val: serde_json::Value =
        serde_json::from_str(txt).map_err(|e| format!("php.net states: {e}"))?;
    let majors = val.as_object().ok_or("unexpected php.net states JSON")?;
    let date = |b: &serde_json::Value, k: &str| -> String {
        b.get(k)
            .and_then(|x| x.as_str())
            .map(|s| s.chars().take(10).collect())
            .unwrap_or_default()
    };
    let mut out = std::collections::HashMap::new();
    for branches in majors.values().filter_map(|m| m.as_object()) {
        for (line, b) in branches {
            out.insert(
                line.clone(),
                PhpBranch {
                    state: b.get("state").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    active_end: date(b, "active_support_end"),
                    security_end: date(b, "security_support_end"),
                },
            );
        }
    }
    Ok(out)
}

/// Dropdown status and note for a PHP branch.
fn php_branch_label(b: &PhpBranch) -> (String, String) {
    match b.state.as_str() {
        "stable" => (
            "Active".into(),
            // Kept short: it has to fit beside the install window's dropdown.
            format!("active until {}, security until {}", b.active_end, b.security_end),
        ),
        "security" => (
            "Security".into(),
            format!("security fixes only, until {}", b.security_end),
        ),
        "eol" => ("EOL".into(), format!("end of life since {}", b.security_end)),
        _ => (String::new(), String::new()),
    }
}

/// `cur` = installed version; `None` means the component is not installed at all
/// (first-run bootstrap): every branch php.net still supports is then a
/// candidate, newest first. Each candidate carries its support state.
pub fn feed_php(cur: Option<&Ver>, allow_major: bool) -> Result<Vec<Info>, String> {
    let shown = cur.map(|c| c.show()).unwrap_or_else(|| "not installed".into());
    // Without php.net's states the list is still usable, just unlabelled.
    let states = http::http_get_text(PHP_STATES)
        .and_then(|t| parse_php_states(&t))
        .unwrap_or_default();
    let txt = http::http_get_text(PHP_JSON)?;
    let val: serde_json::Value =
        serde_json::from_str(&txt).map_err(|e| format!("releases.json PHP: {e}"))?;
    let obj = val.as_object().ok_or("unexpected PHP releases.json")?;
    let mut out: Vec<(Ver, Info)> = Vec::new();
    for (_line, e) in obj {
        let Some(v) = e
            .get("version")
            .and_then(|x| x.as_str())
            .and_then(Ver::parse)
        else {
            continue;
        };
        if let Some(c) = cur {
            if !ver_cmp(&v, c).is_gt() {
                continue;
            }
            if !allow_major && !v.same_line(c) {
                continue;
            }
        }
        // mod_php needs a thread-safe (ZTS) build: "ts-vsNN-x64" is that flavour.
        let flavors: Vec<&serde_json::Value> = e
            .as_object()
            .map(|o| {
                o.iter()
                    .filter(|(k, _)| {
                        k.starts_with("ts-vs") && k.ends_with("-x64") && !k.contains("debug")
                    })
                    .map(|(_, v)| v)
                    .collect()
            })
            .unwrap_or_default();
        let Some(f) = flavors.first() else { continue };
        let Some(zip) = f.get("zip") else { continue };
        let Some(path) = zip.get("path").and_then(|x| x.as_str()) else {
            continue;
        };
        let sha = zip
            .get("sha256")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_lowercase();
        let size = zip
            .get("size")
            .and_then(|x| x.as_str())
            .map(human_size)
            .unwrap_or(0);
        let line = format!("{}.{}", v.0[0], v.0[1]);
        let branch = states.get(&line);
        // A fresh install only offers branches that still get fixes.
        if cur.is_none() && branch.is_some_and(|b| b.state == "eol") {
            continue;
        }
        let (status, note) = branch.map(php_branch_label).unwrap_or_default();
        out.push((
            v,
            Info {
                comp: Comp::Php,
                installed: shown.clone(),
                available: v.show(),
                url: format!("{PHP_BASE}/{path}"),
                file: path.to_string(),
                sha256: sha,
                size,
                note,
                line,
                status,
            },
        ));
    }
    out.sort_by(|a, b| ver_cmp(&b.0, &a.0));
    Ok(out.into_iter().map(|(_, i)| i).collect())
}

pub fn feed_apache(cur: Option<&Ver>, allow_major: bool) -> Result<Vec<Info>, String> {
    let shown = cur.map(|c| c.show()).unwrap_or_else(|| "not installed".into());
    let html = http::http_get_text(AL_PAGE)?;
    let found = scan_apachelounge(&html);
    if found.is_empty() {
        return Err(format!("no Win64-VS17 archive found on {AL_PAGE}"));
    }
    let mut cands: Vec<(Ver, String)> = found
        .into_iter()
        .filter(|(v, _)| match cur {
            Some(c) => ver_cmp(v, c).is_gt() && (allow_major || v.same_line(c)),
            None => true,
        })
        .collect();
    // A version re-cut on a newer date: keep the newest build per version.
    cands.sort_by(|a, b| ver_cmp(&b.0, &a.0).then_with(|| b.1.cmp(&a.1)));
    cands.dedup_by(|a, b| a.0 == b.0);
    let mut out = Vec::new();
    for (v, name) in cands {
        // Checksum sidecar published next to the zip; optional but used when present.
        let mut sha = String::new();
        if let Ok(t) = http::http_get_text(&format!("{AL_BASE}/{name}.txt")) {
            if let Some(h) = parse_sha256_sidecar(&t) {
                sha = h;
            }
        }
        let note = apachelounge_build_date(&name)
            .map(|d| format!("Apache Lounge build of {d}"))
            .unwrap_or_default();
        out.push(Info {
            comp: Comp::Apache,
            installed: shown.clone(),
            available: v.show(),
            url: format!("{AL_BASE}/{name}"),
            file: name,
            sha256: sha,
            size: 0,
            note,
            line: format!("{}.{}", v.0[0], v.0[1]),
            status: String::new(),
        });
    }
    Ok(out)
}

/// `httpd-2.4.66-251206-win64-VS17.zip` -> "2025-12-06".
fn apachelounge_build_date(name: &str) -> Option<String> {
    let d = name.split('-').nth(2)?;
    (d.len() == 6 && d.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("20{}-{}-{}", &d[..2], &d[2..4], &d[4..]))
}

/// Scan an HTML page for `httpd-X.Y.Z-YYMMDD-Win64-VS17.zip` names.
fn scan_apachelounge(html: &str) -> Vec<(Ver, String)> {
    let b = html.as_bytes();
    let mut out: Vec<(Ver, String)> = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = find_from(b, i, b"httpd-") {
        let mut j = rel + 6;
        let mut parts = [0u32; 3];
        let mut ok = true;
        for p in parts.iter_mut() {
            let start = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if start == j {
                ok = false;
                break;
            }
            *p = String::from_utf8_lossy(&b[start..j]).parse().unwrap_or(0);
            if j < b.len() && b[j] == b'.' {
                j += 1;
            } else {
                break;
            }
        }
        if !ok || j >= b.len() || b[j] != b'-' {
            i = rel + 6;
            continue;
        }
        // -YYMMDD
        let tail_start = j + 1;
        let mut k = tail_start;
        while k < b.len() && b[k].is_ascii_digit() {
            k += 1;
        }
        let rest = &html[k..(k + 18).min(html.len())].to_ascii_lowercase();
        if rest.starts_with("-win64-vs17.zip") {
            let end = k + "-win64-vs17.zip".len();
            let name = html[rel..end].to_string();
            let v = Ver([parts[0], parts[1], parts[2], 0]);
            if !out.iter().any(|(ov, on)| *ov == v && *on == name) {
                out.push((v, name));
            }
            i = end;
        } else {
            i = rel + 6;
        }
    }
    out
}

fn find_from(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn parse_sha256_sidecar(txt: &str) -> Option<String> {
    let lines: Vec<&str> = txt.lines().map(|l| l.trim()).collect();
    let clean = |s: &str| -> Option<String> {
        let h: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if h.len() == 64 {
            Some(h.to_lowercase())
        } else {
            None
        }
    };
    for (i, l) in lines.iter().enumerate() {
        if !l.to_ascii_uppercase().starts_with("SHA256-CHECKSUM FOR") {
            continue;
        }
        // Some sidecars put the digest after the label, most put it on the next line.
        if let Some(h) = clean(l.split(':').next_back().unwrap_or("")) {
            return Some(h);
        }
        for n in &lines[i + 1..] {
            if n.is_empty() {
                continue;
            }
            if let Some(h) = clean(n) {
                return Some(h);
            }
            break;
        }
    }
    None
}

pub fn feed_mariadb(
    cur: Option<&Ver>,
    allow_major: bool,
    target_line: &str,
) -> Result<Vec<Info>, String> {
    let shown = cur.map(|c| c.show()).unwrap_or_else(|| "not installed".into());
    let txt = http::http_get_text(MDB_API)?;
    let val: serde_json::Value =
        serde_json::from_str(&txt).map_err(|e| format!("rest-api: {e}"))?;
    let majors = val
        .get("major_releases")
        .and_then(|m| m.as_array())
        .ok_or("rest-api: no major_releases field")?;
    struct Line {
        id: String,
        v: Ver,
        status: String,
        eol: String,
    }
    let mut lines: Vec<Line> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for m in majors {
        let id = m.get("release_id").and_then(|x| x.as_str()).unwrap_or("");
        let rstatus = m
            .get("release_status")
            .and_then(|x| x.as_str())
            .unwrap_or("Stable");
        if id.is_empty() {
            continue;
        }
        seen.push(id.to_string());
        let stype = m
            .get("release_support_type")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        // LTS vs mainline "Rolling"; RC/Preview lines are offered too but tagged
        // test so the user can pick them knowingly.
        let status = if rstatus.eq_ignore_ascii_case("Stable") {
            if stype.contains("Long Term") {
                "LTS".to_string()
            } else if stype.eq_ignore_ascii_case("Rolling") {
                "Rolling".to_string()
            } else {
                "Stable".to_string()
            }
        } else {
            format!("{rstatus} test")
        };
        let d = m
            .get("release_eol_date")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(v) = Ver::parse(&format!("{id}.0")) {
            lines.push(Line {
                id: id.to_string(),
                v,
                status,
                eol: d,
            });
        }
    }
    // An explicit target line pins the list; otherwise every line above the
    // installed one (when major jumps are allowed) plus the installed line for
    // patch updates.
    let cur_line = cur
        .map(|c| format!("{}.{}", c.0[0], c.0[1]))
        .unwrap_or_default();
    let target = target_line.trim();
    let today = today_str();
    let wanted: Vec<&Line> = if !target.is_empty() {
        lines.iter().filter(|l| l.id == target).collect()
    } else if let Some(c) = cur {
        let base = Ver([c.0[0], c.0[1], 0, 0]);
        lines
            .iter()
            .filter(|l| {
                let above = ver_cmp(&l.v, &base).is_gt();
                l.id == cur_line || (allow_major && above)
            })
            .collect()
    } else {
        // Fresh install: pin it on an LTS line, never on a rolling or preview one,
        // nor on one past its end of life (the API keeps listing those).
        let lts: Vec<&Line> = lines
            .iter()
            .filter(|l| l.status == "LTS" && !eol_passed(&l.eol, &today))
            .collect();
        if lts.is_empty() {
            lines.iter().collect()
        } else {
            lts
        }
    };
    if wanted.is_empty() {
        return Err(format!(
            "MariaDB {} is no longer in the release lines (available: {})",
            if cur.is_some() {
                shown.as_str()
            } else {
                target
            },
            seen.join(", ")
        ));
    }
    let mut out: Vec<(Ver, Info)> = Vec::new();
    for line in wanted {
        let t = match http::http_get_text(&format!("{MDB_API}/{}/latest/", line.id)) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let v: serde_json::Value = match serde_json::from_str(&t) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let rels = match v.get("releases").and_then(|r| r.as_object()) {
            Some(r) => r,
            None => continue,
        };
        let mut best: Option<(Ver, String, String, String, u64)> = None;
        for (rid, r) in rels {
            let Some(rv) = Ver::parse(rid) else { continue };
            if let Some(c) = cur {
                if !ver_cmp(&rv, c).is_gt() {
                    continue;
                }
            }
            let files = match r.get("files").and_then(|f| f.as_array()) {
                Some(f) => f,
                None => continue,
            };
            for f in files {
                let name = f.get("file_name").and_then(|x| x.as_str()).unwrap_or("");
                let low = name.to_ascii_lowercase();
                // mariadb-<v>-winx64.zip only: the debugsymbols archive is twice
                // the size and carries nothing we can use.
                if !low.ends_with("-winx64.zip") || low.contains("debug") {
                    continue;
                }
                let url = f
                    .get("file_download_url")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string()
                    .replace("http://", "https://");
                let sha = f
                    .get("checksum")
                    .and_then(|c| c.get("sha256sum"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let size = f.get("file_size").and_then(|x| x.as_u64()).unwrap_or(0);
                if best
                    .as_ref()
                    .map(|(bv, _, _, _, _)| ver_cmp(&rv, bv).is_gt())
                    .unwrap_or(true)
                {
                    best = Some((rv, name.to_string(), url, sha, size));
                }
            }
        }
        if let Some((rv, name, url, sha, size)) = best {
            let mut note = String::new();
            if !line.eol.is_empty() {
                note = format!(
                    "line {} EOL {}{}",
                    line.id,
                    line.eol,
                    if eol_passed(&line.eol, &today) { " (passed)" } else { "" }
                );
            } else if line.status == "Rolling" {
                // Leaving an LTS line for this one trades years of fixes for months.
                note = "rolling release: supported until the next one ships".into();
            }
            out.push((
                rv,
                Info {
                    comp: Comp::Mysql,
                    installed: shown.clone(),
                    available: rv.show(),
                    url,
                    file: name,
                    sha256: sha,
                    size,
                    note,
                    line: line.id.clone(),
                    status: line.status.clone(),
                },
            ));
        }
    }
    // Stable lines first (newest first); RC/Preview stay offered but never
    // become the default suggestion.
    out.sort_by(|a, b| {
        let rank = |i: &Info| if i.status.contains("test") { 1 } else { 0 };
        rank(&a.1)
            .cmp(&rank(&b.1))
            .then_with(|| ver_cmp(&b.0, &a.0))
    });
    Ok(out.into_iter().map(|(_, i)| i).collect())
}

/// One-line label for the target dropdown: "13.0.2 (Rolling)".
/// phpMyAdmin: GitHub releases announce the versions, the canonical
/// files.phpmyadmin.net host carries the zips plus a plain `<zip>.sha256` sidecar.
/// The all-languages flavour, so the locale/ tree is fully populated.
pub fn feed_phpmyadmin(cur: Option<&Ver>, allow_major: bool) -> Result<Vec<Info>, String> {
    let shown = cur.map(|c| c.show()).unwrap_or_else(|| "not installed".into());
    let txt = http::http_get_text(PMA_API)?;
    let val: serde_json::Value =
        serde_json::from_str(&txt).map_err(|e| format!("GitHub releases phpMyAdmin: {e}"))?;
    let arr = val.as_array().ok_or("unexpected GitHub releases JSON")?;
    let mut cands: Vec<Ver> = Vec::new();
    for e in arr {
        if e.get("draft").and_then(|x| x.as_bool()).unwrap_or(false)
            || e.get("prerelease").and_then(|x| x.as_bool()).unwrap_or(false)
        {
            continue;
        }
        // Release titles look like "5.2.3"; fall back to tags RELEASE_5_2_3.
        let name = e.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let tag = e.get("tag_name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let raw = if name.is_empty() || Ver::parse(&name).is_none() {
            tag.strip_prefix("RELEASE_")
                .map(|t| t.replace('_', "."))
                .unwrap_or(name)
        } else {
            name
        };
        // "5.2.3-rc1" / "6.0.0-beta1": title or tag carries a suffix we reject.
        let Some(v) = Ver::parse(&raw) else { continue };
        if raw != v.show() && !raw.starts_with(&format!("{}.", v.show())) {
            continue;
        }
        if let Some(c) = cur {
            if !ver_cmp(&v, c).is_gt() || (!allow_major && !v.same_line(c)) {
                continue;
            }
        }
        if !cands.contains(&v) {
            cands.push(v);
        }
    }
    cands.sort_by(|a, b| ver_cmp(b, a));
    // A fresh install only ever takes the newest release: skip fetching dozens
    // of checksum sidecars for the others.
    if cur.is_none() {
        cands.truncate(1);
    }
    let mut out = Vec::new();
    for v in cands {
        let ver = v.show();
        let file = format!("phpMyAdmin-{ver}-all-languages.zip");
        let url = format!("{PMA_BASE}/{ver}/{file}");
        let mut sha = String::new();
        if let Ok(t) = http::http_get_text(&format!("{url}.sha256")) {
            if let Some(h) = parse_plain_sha256(&t) {
                sha = h;
            }
        }
        out.push(Info {
            comp: Comp::Phpmyadmin,
            installed: shown.clone(),
            available: ver,
            url,
            file,
            sha256: sha,
            size: 0,
            note: String::new(),
            line: String::new(),
            status: String::new(),
        });
    }
    Ok(out)
}

/// Sidecar shaped like `<64 hex>  <filename>` (files.phpmyadmin.net style).
fn parse_plain_sha256(txt: &str) -> Option<String> {
    let tok = txt.split_whitespace().next()?;
    if tok.len() == 64 && tok.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(tok.to_lowercase())
    } else {
        None
    }
}

pub fn target_label(i: &Info) -> String {
    if i.status.is_empty() {
        i.available.clone()
    } else {
        format!("{} ({})", i.available, i.status)
    }
}

/// Both dates as YYYY-MM-DD, so they compare as text; no date means not passed.
fn eol_passed(eol: &str, today: &str) -> bool {
    !eol.is_empty() && eol <= today
}

fn today_str() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if y <= 0 { y + 1 } else { y }, m, d)
}

/// What a fresh install can choose from, newest first: Apache Lounge's 2.4
/// builds, MariaDB's long-term support lines (or the pinned TargetLine), the
/// PHP branches php.net still supports, and the newest phpMyAdmin. An empty
/// list is reported as an error, so the row can say why it has no choice.
pub fn install_choices(target_line: &str) -> Vec<(Comp, Result<Vec<Info>, String>)> {
    Comp::all()
        .into_iter()
        .map(|c| {
            let list = match c {
                Comp::Apache => feed_apache(None, true),
                Comp::Mysql => feed_mariadb(None, true, target_line),
                Comp::Php => feed_php(None, true),
                Comp::Phpmyadmin => feed_phpmyadmin(None, true),
            };
            let list = list.and_then(|l| {
                if l.is_empty() {
                    Err(format!("no published {} build found", c.label()))
                } else {
                    Ok(l)
                }
            });
            (c, list)
        })
        .collect()
}

/// One entry per component, tagged with the component so a feed error can still
/// be attributed to a row in the update window.
pub fn check_all(
    basedir: &Path,
    allow_major: bool,
    target_line: &str,
) -> Vec<(Comp, Result<Vec<Info>, String>)> {
    let mut res: Vec<(Comp, Result<Vec<Info>, String>)> = Comp::all()
        .into_iter()
        .map(|c| {
            let r = match installed_opt(basedir, c) {
                None => Err(format!("{} is not installed", c.label())),
                Some(cur) => match c {
                    Comp::Apache => feed_apache(Some(&cur), allow_major),
                    Comp::Mysql => feed_mariadb(Some(&cur), allow_major, target_line),
                    Comp::Php => feed_php(Some(&cur), allow_major),
                    Comp::Phpmyadmin => feed_phpmyadmin(Some(&cur), allow_major),
                },
            };
            (c, r)
        })
        .collect();
    fill_sizes(&mut res);
    res
}

/// Archive sizes the feeds do not publish (MariaDB's API, Apache Lounge,
/// phpMyAdmin): asked from the download servers, all at once, for display.
fn fill_sizes(res: &mut [(Comp, Result<Vec<Info>, String>)]) {
    std::thread::scope(|s| {
        for info in res
            .iter_mut()
            .filter_map(|(_, r)| r.as_mut().ok())
            .flatten()
            .filter(|i| i.size == 0 && !i.url.is_empty())
        {
            s.spawn(move || {
                if let Some(n) = http::http_size(&info.url) {
                    info.size = n;
                }
            });
        }
    });
}

// ------------------------------------------------------------------ checksum

fn sha256_file(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&data);
    Ok(hex::encode(h.finalize()))
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// --------------------------------------------------------------------- apply

/// Rename journal: replayed in reverse on any failure.
struct Journal {
    ops: Vec<(PathBuf, PathBuf)>,
}

impl Journal {
    fn mv(&mut self, from: &Path, to: &Path) -> Result<(), String> {
        fs::rename(from, to)
            .map_err(|e| format!("rename {} -> {}: {e}", from.display(), to.display()))?;
        self.ops.push((from.to_path_buf(), to.to_path_buf()));
        Ok(())
    }
    fn undo(&mut self, log: &mut dyn FnMut(String, bool)) {
        while let Some((from, to)) = self.ops.pop() {
            if let Err(e) = fs::rename(&to, &from) {
                log(
                    format!(
                        "rollback failed ({} -> {}): {e}",
                        to.display(),
                        from.display()
                    ),
                    true,
                );
            } else {
                log(
                    format!("rollback: {} put back in place", from.display()),
                    false,
                );
            }
        }
    }
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    for e in fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))? {
        let e = e.map_err(|e| e.to_string())?;
        let p = e.path();
        let d = to.join(e.file_name());
        if p.is_dir() {
            copy_tree(&p, &d)?;
        } else {
            fs::copy(&p, &d).map_err(|er| format!("{}: {er}", d.display()))?;
        }
    }
    Ok(())
}

fn tree_size(from: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(rd) = fs::read_dir(from) {
        for e in rd.flatten() {
            let p = e.path();
            total += if p.is_dir() {
                tree_size(&p)
            } else {
                fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
            };
        }
    }
    total
}

fn remove_tree(p: &Path) {
    if p.exists() {
        if p.is_dir() {
            let _ = fs::remove_dir_all(p);
        } else {
            let _ = fs::remove_file(p);
        }
    }
}

fn mib(n: u64) -> String {
    format!("{:.1} MiB", n as f64 / 1_048_576.0)
}

/// Size for things that are not megabyte-scale (the scratch folder is mostly
/// loose session and temp files).
fn hb(n: u64) -> String {
    if n >= 1_048_576 {
        mib(n)
    } else if n >= 1024 {
        format!("{:.0} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

/// Extract `root` of a normalised tree out of the archive.
/// Locate the real tree inside the extraction dir: archives differ in nesting
/// (PHP and MariaDB use one root folder, Apache Lounge uses "Apache24/").
fn archive_root(dst: &Path, marker: &str) -> PathBuf {
    if dst.join(marker).is_file() {
        return dst.to_path_buf();
    }
    let Ok(rd) = fs::read_dir(dst) else {
        return dst.to_path_buf();
    };
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        if p.join(marker).is_file() {
            return p;
        }
        if let Ok(rd2) = fs::read_dir(&p) {
            for e2 in rd2.flatten() {
                let p2 = e2.path();
                if p2.is_dir() && p2.join(marker).is_file() {
                    return p2;
                }
            }
        }
    }
    dst.to_path_buf()
}

fn work_dir(basedir: &Path) -> PathBuf {
    basedir.join("tmp").join("update")
}

fn ex_dir(basedir: &Path, comp: Comp) -> PathBuf {
    work_dir(basedir).join(format!("ex-{}", comp.dir()))
}

/// Drop the extraction shell once the tree that was inside it has been moved
/// into place.
pub fn clean_extract(basedir: &Path, comp: Comp) {
    remove_tree(&ex_dir(basedir, comp));
}

/// The archive has done its job and nothing needs it any more: delete it, then
/// the scratch folder itself once it holds nothing. A failed install keeps its
/// archive on purpose, so a retry does not pay for the download twice.
/// Never touch `<basedir>/tmp` itself: php.ini points upload_tmp_dir and
/// session.save_path at it.
pub fn drop_archive(basedir: &Path, file: &str, log: &mut dyn FnMut(String, bool)) {
    let work = work_dir(basedir);
    let archive = work.join(file);
    if archive.is_file() {
        let sz = fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
        if fs::remove_file(&archive).is_ok() {
            log(format!("downloaded archive deleted: {file} ({})", mib(sz)), false);
        }
    }
    let empty = fs::read_dir(&work).map(|mut d| d.next().is_none()).unwrap_or(false);
    if empty {
        remove_tree(&work);
    }
}

/// Sweep the scratch folder when a job is finished: the package must not carry
/// 100+ MB of archives, and `<basedir>/tmp` itself only exists to serve the
/// servers while they run. ensure_runtime_dirs() puts it back before the next
/// start, so an idle package stays clean. A server that is still running keeps
/// its files open in there, and then the folder is left alone.
pub fn sweep_tmp(basedir: &Path, log: &mut dyn FnMut(String, bool)) {
    let tmp = basedir.join("tmp");
    if !tmp.is_dir() {
        return;
    }
    let freed = tree_size(&tmp);
    remove_tree(&tmp);
    if tmp.exists() {
        log(
            "could not remove tmp/: a server still has files open in it".into(),
            true,
        );
    } else {
        log(format!("tmp/ removed ({})", hb(freed)), false);
    }
}

/// Folders the ini files point at (php.ini session.save_path and upload_tmp_dir,
/// my.ini tmpdir, PHP's log file). A missing save_path silently kills sessions
/// (phpMyAdmin login) and MariaDB cannot sort without its tmpdir, so this runs
/// on every launch and again before any module starts.
pub fn ensure_runtime_dirs(basedir: &Path, log: &mut dyn FnMut(String, bool)) {
    for d in ["tmp", "php\\logs"] {
        let p = basedir.join(d);
        if !p.is_dir() {
            if let Err(e) = fs::create_dir_all(&p) {
                log(format!("cannot create {}: {e}", p.display()), true);
            }
        }
    }
}

/// Steps 1..5 shared by a component update and by the first-run installer:
/// fetch the archive (kept in the cache), verify the published checksum, extract
/// it and prove the tree really carries the advertised version. Returns the real
/// tree root (archives differ in nesting) and the marker binary that was found
/// inside the archive.
pub fn fetch_verify(
    basedir: &Path,
    info: &Info,
    log: &mut dyn FnMut(String, bool),
    prog: &mut dyn FnMut(u64, u64),
) -> Result<(PathBuf, &'static str), String> {
    let comp = info.comp;

    // Every feed publishes a SHA256 (releases.json, the MariaDB REST API, the
    // Apache Lounge and phpMyAdmin sidecars). None means its fetch failed, and
    // the archive may arrive from a plain-HTTP mirror: nothing would vouch for it.
    if info.sha256.is_empty() {
        return Err(format!(
            "no SHA256 could be fetched for {}: an unverified archive is never installed, retry later",
            info.file
        ));
    }

    // 1. archive
    let work = work_dir(basedir);
    fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let archive = work.join(&info.file);
    if archive.exists() {
        if sha256_file(&archive)? == info.sha256 {
            log(format!("archive already cached: {}", info.file), false);
        } else {
            remove_tree(&archive);
        }
    }
    if !archive.exists() {
        log(
            format!(
                "downloading {} ({})",
                info.url,
                if info.size > 0 {
                    mib(info.size)
                } else {
                    "?".into()
                }
            ),
            false,
        );
        let n = http::http_download(&info.url, &archive, prog)?;
        log(
            format!("archive received: {} ({})", info.file, mib(n)),
            false,
        );
    }

    // 2. checksum
    let got = sha256_file(&archive)?;
    if got != info.sha256 {
        return Err(format!(
            "bad SHA256\n expected {}\n obtained {}\n the archive was not installed",
            info.sha256, got
        ));
    } else {
        log("SHA256 verified".into(), false);
    }

    // 3. inspect archive
    let names: Vec<String> = {
        let f = fs::File::open(&archive).map_err(|e| e.to_string())?;
        let mut ar = zip::ZipArchive::new(f).map_err(|e| format!("zip: {e}"))?;
        (0..ar.len())
            .filter_map(|i| {
                ar.by_index(i)
                    .ok()
                    .and_then(|z| z.name().map(|n| n.replace('\\', "/")).ok())
            })
            .collect()
    };
    let marker = comp.exe_candidates().iter().copied().find(|c| {
        names
            .iter()
            .any(|n| n == c || n.ends_with(&format!("/{c}")))
    });
    let Some(marker) = marker else {
        return Err(format!(
            "archive has no {} (nor {}): refused",
            comp.exe_candidates()[0],
            comp.exe()
        ));
    };
    if comp == Comp::Mysql && names.iter().any(|n| n == "data" || n.starts_with("data/")) {
        return Err("the MariaDB archive contains a data/ folder: refused".into());
    }
    if comp == Comp::Php && !names.iter().any(|n| n.ends_with("php8apache2_4.dll")) {
        log(
            "warning: the archive has no php8apache2_4.dll (mod_php)".into(),
            true,
        );
    }

    // 4. extract
    let dst = ex_dir(basedir, comp);
    remove_tree(&dst);
    fs::create_dir_all(&dst).map_err(|e| e.to_string())?;
    {
        let f = fs::File::open(&archive).map_err(|e| e.to_string())?;
        let mut ar = zip::ZipArchive::new(f).map_err(|e| format!("zip: {e}"))?;
        ar.extract(&dst).map_err(|e| format!("extract: {e}"))?;
    }
    let root = archive_root(&dst, marker);
    let newexe = root.join(marker);
    if !newexe.is_file() {
        return Err(format!("after extract, {} is missing", newexe.display()));
    }

    // 5. the new binary must really be the advertised version
    if comp == Comp::Phpmyadmin {
        let rd = format!("RELEASE-DATE-{}", info.available);
        if !root.join(&rd).is_file() {
            return Err(format!(
                "the extracted tree has no {rd}: not the announced phpMyAdmin build"
            ));
        }
    } else {
        match pe_version(&newexe) {
            Some(v) if v.show() == info.available => {}
            Some(v) => {
                return Err(format!(
                    "extracted binary is {} but upstream announced {}",
                    v.show(),
                    info.available
                ))
            }
            None => return Err("unreadable PE version in the extracted binary".into()),
        }
    }
    Ok((root, marker))
}

/// Download + verify + swap one component. The modules must already be stopped.
/// What a successful apply() leaves behind.
pub struct Applied {
    pub comp: Comp,
    pub backup: PathBuf,
    /// File name of the server binary in the new tree ("mariadbd.exe" after a
    /// MariaDB major jump), so the caller can update BinaryNames.
    pub exe: String,
}

pub fn apply(
    basedir: &Path,
    info: &Info,
    keep_backups: usize,
    data_backup_limit_mb: u64,
    log: &mut dyn FnMut(String, bool),
    prog: &mut dyn FnMut(u64, u64),
) -> Result<Applied, String> {
    let comp = info.comp;
    let old = basedir.join(comp.dir());
    if !old.is_dir() {
        return Err(format!("missing folder: {}", old.display()));
    }

    let (root, marker) = fetch_verify(basedir, info, log, prog)?;
    let dst = ex_dir(basedir, comp);
    if comp == Comp::Mysql {
        let jump = match (Ver::parse(&info.installed), Ver::parse(&info.available)) {
            (Some(from), Some(to)) => !from.same_line(&to),
            _ => true,
        };
        if jump {
            log(
                format!(
                    "MariaDB line jump {} -> {}: the updater will checkpoint the datadir \
                     with the old build, then run mariadb-upgrade on the new one",
                    info.installed, info.available
                ),
                true,
            );
        }
    }
    let backup = basedir.join(".backup").join(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "unknown".into()),
    );
    fs::create_dir_all(&backup).map_err(|e| format!("{}: {e}", backup.display()))?;
    log(format!("backup: {}", backup.display()), false);

    let mut jr = Journal { ops: Vec::new() };
    let res: Result<(), String> = (|| {
        // preserve user configuration
        match comp {
            Comp::Apache => {
                let conf = old.join("conf");
                if conf.is_dir() {
                    remove_tree(&root.join("conf"));
                    copy_tree(&conf, &root.join("conf"))?;
                    log("apache conf/ kept".into(), false);
                }
                if !root.join("logs").is_dir() {
                    fs::create_dir_all(root.join("logs")).map_err(|e| e.to_string())?;
                }
                copy_if_missing(&old, &root, "cgi-bin", log);
            }
            Comp::Php => {
                let ini = old.join("php.ini");
                if ini.is_file() {
                    fs::copy(&ini, root.join("php.ini")).map_err(|e| e.to_string())?;
                    log("php.ini kept".into(), false);
                    warn_missing_extensions(&ini, &root.join("ext"), log);
                }
                copy_if_missing(&old, &root, "extras", log);
            }
            Comp::Phpmyadmin => {
                let cfg = old.join("config.inc.php");
                if cfg.is_file() {
                    fs::copy(&cfg, root.join("config.inc.php")).map_err(|e| e.to_string())?;
                    log("config.inc.php kept".into(), false);
                }
                // The cache/upload dirs config.inc.php points at are not part
                // of the official zip.
                copy_if_missing(&old, &root, "tmp", log);
                copy_if_missing(&old, &root, "upload_tmp", log);
            }
            Comp::Mysql => {
                let ini = old.join("bin").join("my.ini");
                if ini.is_file() {
                    fs::copy(&ini, root.join("bin").join("my.ini")).map_err(|e| e.to_string())?;
                    log("my.ini kept".into(), false);
                }
                let data = old.join("data");
                if data.is_dir() {
                    let sz = tree_size(&data);
                    if sz > data_backup_limit_mb * 1_048_576 {
                        return Err(format!(
                            "the datadir is {}, above the backup limit ({} MB)\n\
                             lower DataBackupLimitMB in the INI after checking",
                            mib(sz),
                            data_backup_limit_mb
                        ));
                    }
                    log(
                        format!("safety copy of the datadir ({}), please wait", mib(sz)),
                        false,
                    );
                    copy_tree(&data, &backup.join("data"))?;
                    jr.mv(&data, &root.join("data"))?;
                    log("datadir moved into the new tree".into(), false);
                }
            }
        }

        // atomic-ish swaps on the same volume
        jr.mv(&old, &backup.join(comp.dir()))?;
        log(format!("{} moved into the backup", comp.dir()), false);
        jr.mv(&root, &old)?;
        log(format!("new {} tree in place", comp.dir()), false);
        Ok(())
    })();

    if let Err(e) = res {
        jr.undo(log);
        remove_tree(&dst);
        return Err(e);
    }

    remove_tree(&dst);
    drop_archive(basedir, &info.file, log);
    gc_backups(basedir, keep_backups, log);
    if comp == Comp::Apache || comp == Comp::Php {
        patch_compat(basedir, log);
    }
    log(
        format!(
            "{} updated: {} -> {}",
            comp.label(),
            info.installed,
            info.available
        ),
        false,
    );
    Ok(Applied {
        comp,
        backup,
        exe: marker.rsplit('/').next().unwrap_or(marker).to_string(),
    })
}

// ---------------------------------------------------------- compatibility patches

/// Where mod_php is wired in, as httpd.conf includes it.
pub const PHP_CONF: &str = "apache\\conf\\extra\\httpd-ramp.conf";
const PHP_CONF_INCLUDE: &str = "conf/extra/httpd-ramp.conf";

/// Re-assert known compatibility fixes after swapping Apache or PHP.
/// These fix crashes that appear when a new PHP meets an existing Apache config:
///  - PHPINIDir + mod_php >= 8.5 => httpd worker crash (0xC0000005) on the first
///    request. The control panel exports PHPRC in the httpd.exe process
///    environment instead (with_php_env in main.rs); the conf's SetEnv PHPRC
///    only covers request scope, not module init.
///  - php.ini: session.sid_length / session.sid_bits_per_character are deprecated
///    since PHP 8.5 and pollute the error log at every start; commented out.
///
/// Idempotent: only rewrites files when something actually changes.
pub fn patch_compat(basedir: &Path, log: &mut dyn FnMut(String, bool)) {
    adopt_php_conf(basedir, log);
    // Path portability applies regardless of the PHP version: the tree is
    // unzipped wherever the user puts it, and a php.ini carried over from
    // another package may hardcode drive-relative `\<folder>\...` paths, plus
    // possibly a stale extension_dir baked in at build time.
    patch_php_ini_paths(basedir, log);
    ensure_ini_fallback(basedir, log);
    disable_php_cgi_alias(basedir, log);
    crate::install::fix_ssl_conf(basedir, log);
    let php_exe = basedir.join("php").join("php.exe");
    let php_new = pe_version(&php_exe)
        .map(|v| ver_cmp(&v, &Ver([8, 5, 0, 0])) != std::cmp::Ordering::Less)
        .unwrap_or(false);
    if !php_new {
        log("compat: PHP < 8.5 (or unknown), no version-specific patch needed".into(), false);
        return;
    }
    patch_php_conf(basedir, log);
    patch_php_ini(basedir, log);
}

fn read_text(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok()
}

/// Trees set up before PHP_CONF got its name load mod_php from another
/// conf/extra file. Adopt that file under PHP_CONF, the name every patch looks
/// for, and point httpd.conf's Include at it. The file is recognised by what it
/// does (it loads php_module), not by its old name.
fn adopt_php_conf(basedir: &Path, log: &mut dyn FnMut(String, bool)) {
    let target = basedir.join(PHP_CONF);
    let httpd = basedir.join("apache\\conf\\httpd.conf");
    if target.exists() {
        return;
    }
    let Some(text) = read_text(&httpd) else {
        return;
    };
    let include_arg = |line: &str| -> Option<String> {
        let rest = line.trim_start().strip_prefix("Include")?;
        let rest = rest.strip_prefix("Optional").unwrap_or(rest);
        rest.starts_with(char::is_whitespace)
            .then(|| rest.trim().trim_matches('"').to_string())
    };
    let loads_php = |p: &Path| {
        read_text(p).is_some_and(|body| {
            body.lines().any(|l| {
                let l = l.trim_start().to_ascii_lowercase();
                l.starts_with("loadmodule") && l.contains("php_module")
            })
        })
    };
    let resolve = |arg: &str| {
        let rel = arg.replace('/', "\\");
        if Path::new(&rel).is_absolute() {
            PathBuf::from(rel)
        } else {
            basedir.join("apache").join(rel)
        }
    };
    let Some((arg, old)) = text
        .lines()
        .filter_map(include_arg)
        .map(|a| {
            let p = resolve(&a);
            (a, p)
        })
        .find(|(_, p)| loads_php(p))
    else {
        return;
    };
    // Only a file sitting where the new one goes is moved: an Include that
    // points into another tree is that tree's business.
    let dir = |p: &Path| p.parent().and_then(|d| fs::canonicalize(d).ok());
    if dir(&old).is_none() || dir(&old) != dir(&target) {
        return;
    }
    if let Err(e) = fs::rename(&old, &target) {
        log(format!("compat: cannot rename {} to {}: {e}", old.display(), target.display()), true);
        return;
    }
    let nl = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if include_arg(line).as_deref() == Some(arg.as_str()) {
            out.push_str(&line.replace(&arg, PHP_CONF_INCLUDE));
        } else {
            out.push_str(line);
        }
        out.push_str(nl);
    }
    if let Err(e) = fs::write(&httpd, out) {
        // httpd.conf still names the old file: put it back.
        let _ = fs::rename(&target, &old);
        log(format!("compat: cannot write {}: {e}", httpd.display()), true);
        return;
    }
    let old_name = old
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    log(
        format!("compat: conf/extra/{old_name} renamed to httpd-ramp.conf (it wires PHP into Apache)"),
        false,
    );
}

fn patch_php_conf(basedir: &Path, log: &mut dyn FnMut(String, bool)) {
    let f = basedir.join(PHP_CONF);
    let Some(text) = read_text(&f) else {
        log("compat: httpd-ramp.conf not readable, skipped".into(), true);
        return;
    };
    let mut has_phprc = false;
    let mut commented = 0usize;
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let t = line.trim_start();
        if t.starts_with("SetEnv PHPRC") {
            has_phprc = true;
        }
        if t.to_ascii_lowercase().starts_with("phpinidir") {
            if commented == 0 {
                out.push_str("# patched by the control panel updater: PHPINIDir crashes the\n");
                out.push_str("# httpd worker (0xC0000005) with PHP >= 8.5 mod_php. The panel exports\n");
                out.push_str("# PHPRC into the httpd process environment at start instead.\n");
            }
            out.push('#');
            out.push_str(line);
            out.push('\n');
            commented += 1;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if commented == 0 {
        log("compat: PHPINIDir already absent from httpd-ramp.conf".into(), false);
        return;
    }
    if !has_phprc {
        let phpdir = basedir.join("php").to_string_lossy().replace('\\', "/");
        out.push_str(&format!("SetEnv PHPRC \"{phpdir}\"\n"));
        log("compat: added SetEnv PHPRC to httpd-ramp.conf".into(), false);
    }
    if let Err(e) = fs::write(&f, out) {
        log(format!("compat: cannot write {}: {e}", f.display()), true);
    } else {
        log(
            format!("compat: PHPINIDir disabled in httpd-ramp.conf ({commented} line(s))"),
            false,
        );
    }
}

/// Older PHP configurations map /php-cgi/ onto the php folder and open
/// php-cgi.exe to every client, although PHP runs as mod_php (the CGI handler is
/// commented out). That alias is the CVE-2024-4577 entry point (argument
/// injection into php-cgi.exe) and Apache listens on every interface, so it is
/// commented out, unless a live `Action ... php-cgi` line still relies on it.
fn disable_php_cgi_alias(basedir: &Path, log: &mut dyn FnMut(String, bool)) {
    let f = basedir.join(PHP_CONF);
    let Some(text) = read_text(&f) else {
        return;
    };
    let cgi_in_use = text.lines().any(|l| {
        let t = l.trim_start().to_ascii_lowercase();
        t.starts_with("action") && t.contains("php-cgi")
    });
    if cgi_in_use {
        return;
    }
    let mut n = 0usize;
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let t = line.trim_start().to_ascii_lowercase();
        if t.starts_with("scriptalias") && t.contains("/php-cgi/") {
            out.push('#');
            n += 1;
        }
        out.push_str(line);
        out.push('\n');
    }
    if n == 0 {
        return;
    }
    if let Err(e) = fs::write(&f, out) {
        log(format!("compat: cannot write {}: {e}", f.display()), true);
    } else {
        log(
            "compat: /php-cgi/ alias disabled in httpd-ramp.conf (PHP runs as mod_php; the alias exposed php-cgi.exe, CVE-2024-4577)".into(),
            false,
        );
    }
}

fn patch_php_ini(basedir: &Path, log: &mut dyn FnMut(String, bool)) {
    let f = basedir.join("php").join("php.ini");
    let Some(text) = read_text(&f) else {
        log("compat: php.ini not readable, skipped".into(), true);
        return;
    };
    let mut n = 0usize;
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let t = line.trim_start();
        let key = t.split('=').next().unwrap_or("").trim_end();
        if (key == "session.sid_length" || key == "session.sid_bits_per_character")
            && !t.starts_with(';')
        {
            out.push(';');
            out.push_str(line);
            n += 1;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if n == 0 {
        return;
    }
    if let Err(e) = fs::write(&f, out) {
        log(format!("compat: cannot write {}: {e}", f.display()), true);
    } else {
        log(
            format!("compat: php.ini, {n} deprecated session.sid_* directive(s) commented out"),
            false,
        );
    }
}

/// php.ini directives that must point inside the package tree. A php.ini
/// carried over from another package may hardcode drive-relative paths
/// (`\<folder>\php\ext` resolves on whatever drive is current), and the build
/// machine's absolute path may be baked into `extension_dir`. The keys below
/// follow the package layout, so they are re-rooted onto the current basedir
/// (idempotent: already-correct values are left untouched).
fn ini_path_keys(basedir: &Path) -> Vec<(&'static str, String, bool)> {
    let abs = |sub: &str| basedir.join(sub).to_string_lossy().into_owned();
    // (key, value, target must already be an existing file)
    vec![
        ("extension_dir", abs("php\\ext"), false),
        ("include_path", abs("php\\PEAR"), false),
        ("upload_tmp_dir", abs("tmp"), false),
        ("session.save_path", abs("tmp"), false),
        ("error_log", abs("php\\logs\\php_error_log"), false),
        ("browscap", abs("php\\extras\\browscap.ini"), true),
        ("curl.cainfo", abs("apache\\bin\\curl-ca-bundle.crt"), true),
        ("openssl.cafile", abs("apache\\bin\\curl-ca-bundle.crt"), true),
    ]
}

fn patch_php_ini_paths(basedir: &Path, log: &mut dyn FnMut(String, bool)) {
    let f = basedir.join("php").join("php.ini");
    let Some(text) = read_text(&f) else {
        log("compat: php.ini not readable, path portability skipped".into(), true);
        return;
    };
    let want = ini_path_keys(basedir);
    let mut n = 0usize;
    let mut m = 0usize;
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let t = line.trim_start();
        let key = t.split('=').next().unwrap_or("").trim_end();
        let eq = line.find('=');
        let hit = if t.starts_with(';') || key.is_empty() || eq.is_none() {
            None
        } else {
            want.iter().find(|(k, _, _)| k.eq_ignore_ascii_case(key))
        };
        match (hit, eq) {
            (Some((_, val, must_exist)), Some(eq)) => {
                if *must_exist && !std::path::Path::new(val).is_file() {
                    // Pointing at a missing file breaks the feature outright
                    // (curl/openssl: cURL error 77); commented out, curl falls
                    // back to the Windows certificate store instead.
                    out.push(';');
                    out.push_str(line);
                    m += 1;
                } else {
                    let prefix = line[..eq].trim_end();
                    let nl = format!("{prefix} = \"{val}\"");
                    if nl != line {
                        n += 1;
                    }
                    out.push_str(&nl);
                }
            }
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    if n > 0 || m > 0 {
        if let Err(e) = fs::write(&f, &out) {
            log(format!("compat: cannot rewrite paths in {}: {e}", f.display()), true);
        } else {
            if n > 0 {
                log(
                    format!("compat: php.ini, {n} path directive(s) re-rooted onto the package tree"),
                    false,
                );
            }
            if m > 0 {
                log(
                    format!("compat: php.ini, {m} directive(s) commented out: target file not in the package"),
                    false,
                );
            }
        }
    }
    // The re-rooted ini points sessions/uploads at these dirs; PHP creates the
    // log file but not its folder.
    ensure_runtime_dirs(basedir, log);
}

/// mod_php also scans httpd.exe's own directory for a php.ini when the process
/// env has no PHPRC (Apache launched by double-click, outside the panel).
/// Keep a synchronised mirror of php\php.ini next to httpd.exe so both launch
/// modes read the same configuration.
pub fn ensure_ini_fallback(basedir: &Path, log: &mut dyn FnMut(String, bool)) {
    let src = basedir.join("php").join("php.ini");
    let dst_dir = basedir.join("apache").join("bin");
    if !src.is_file() || !dst_dir.is_dir() {
        return;
    }
    let txt = match fs::read_to_string(&src) {
        Ok(t) => t,
        Err(_) => return,
    };
    let dst = dst_dir.join("php.ini");
    if let Ok(cur) = fs::read_to_string(&dst) {
        if cur == txt {
            return;
        }
    }
    match fs::write(&dst, &txt) {
        Ok(()) => log(
            "compat: php.ini mirrored to apache\\bin (fallback when Apache is launched without the panel)".into(),
            false,
        ),
        Err(e) => log(format!("compat: cannot mirror php.ini to {}: {e}", dst.display()), true),
    }
}

fn copy_if_missing(old: &Path, root: &Path, sub: &str, log: &mut dyn FnMut(String, bool)) {
    let src = old.join(sub);
    let dst = root.join(sub);
    if src.is_dir() && !dst.is_dir() {
        if let Err(e) = copy_tree(&src, &dst) {
            log(format!("copy of {sub} skipped: {e}"), true);
        } else {
            log(format!("{sub} carried over from the old build"), false);
        }
    }
}

/// php.ini lines that reference extensions absent from the new ext/ set.
fn warn_missing_extensions(ini: &Path, ext_dir: &Path, log: &mut dyn FnMut(String, bool)) {
    let Ok(txt) = fs::read_to_string(ini) else {
        return;
    };
    let mut missing: Vec<String> = Vec::new();
    for line in txt.lines() {
        let l = line.trim();
        let Some(rest) = l
            .strip_prefix("extension=")
            .or_else(|| l.strip_prefix("zend_extension="))
        else {
            continue;
        };
        let v = rest.trim();
        let name = if let Some(q) = v.strip_prefix('"') {
            q.split('"').next().unwrap_or("").to_string()
        } else {
            v.split([';', '\t', ' ']).next().unwrap_or("").to_string()
        };
        if name.contains('\\') || name.contains('/') || name.ends_with(".dll") {
            if ext_dir.join(&name).is_file() {
                continue;
            }
            missing.push(name);
            continue;
        }
        let hit = ext_dir.join(format!("php_{name}.dll")).is_file()
            || fs::read_dir(ext_dir).is_ok_and(|rd| {
                rd.flatten().any(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with(&format!("php_{name}-"))
                })
            });
        if !hit {
            missing.push(name);
        }
    }
    if !missing.is_empty() {
        let shown = if missing.len() > 6 {
            format!("{} (+{} more)", missing[..6].join(", "), missing.len() - 6)
        } else {
            missing.join(", ")
        };
        log(
            format!("warning: extensions missing from the new build: {shown}"),
            true,
        );
    }
}

fn gc_backups(basedir: &Path, keep: usize, log: &mut dyn FnMut(String, bool)) {
    if keep == 0 {
        return;
    }
    let dir = basedir.join(".backup");
    let Ok(rd) = fs::read_dir(&dir) else { return };
    let mut kids: Vec<(u64, PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().parse::<u64>().ok()?;
            Some((n, e.path()))
        })
        .collect();
    kids.sort_by_key(|k| std::cmp::Reverse(k.0));
    for (_, p) in kids.into_iter().skip(keep) {
        log(format!("removed backup {}", p.display()), false);
        remove_tree(&p);
    }
}

/// Put back the previous tree after a failed smoke test. Binaries only: the
/// datadir may already have been migrated, its copy is left alone.
/// Newest .backup/<ts> that still holds a copy of this component.
pub fn find_backup(basedir: &Path, comp: Comp) -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = fs::read_dir(basedir.join(".backup")) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && p.join(comp.dir()).is_dir() {
                found.push(p);
            }
        }
    }
    found.sort();
    found.pop()
}

pub fn rollback(basedir: &Path, comp: Comp, backup: &Path, log: &mut dyn FnMut(String, bool)) {
    let cur = basedir.join(comp.dir());
    let prev = backup.join(comp.dir());
    if !prev.is_dir() {
        log(
            format!("rollback failed: {} is missing", prev.display()),
            true,
        );
        return;
    }
    let trash = backup.join(format!("{}-failed", comp.dir()));
    let mut steps: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut parked: Option<PathBuf> = None;
    if comp == Comp::Mysql {
        // The live datadir may carry the new build's on-disk format (the redo
        // log refuses an older server). Park it, then move the pre-update
        // safety copy back into the old tree: a restore means "back to the
        // state the update started from".
        let live = cur.join("data");
        let safety = backup.join("data");
        if live.is_dir() && !prev.join("data").exists() {
            if safety.is_dir() {
                let park = backup.join(format!(
                    "data-live-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                ));
                steps.push((live, park.clone()));
                steps.push((safety, prev.join("data")));
                parked = Some(park);
            } else {
                steps.push((live, prev.join("data")));
            }
        }
    }
    steps.push((cur.clone(), trash.clone()));
    steps.push((prev.clone(), cur.clone()));
    let mut done: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut failed: Option<String> = None;
    for (f, t) in steps {
        if let Err(e) = fs::rename(&f, &t) {
            failed = Some(format!("{} -> {}: {e}", f.display(), t.display()));
            break;
        }
        done.push((f, t));
    }
    if let Some(msg) = failed {
        for (f, t) in done.into_iter().rev() {
            if let Err(e2) = fs::rename(&t, &f) {
                log(
                    format!("undo failed ({} -> {}): {e2}", t.display(), f.display()),
                    true,
                );
            }
        }
        log(
            format!(
                "partial rollback ({msg})\nmanual restore: move {} back over {}",
                prev.display(),
                cur.display()
            ),
            true,
        );
        return;
    }
    log(
        format!("{} restored from {}", comp.label(), prev.display()),
        false,
    );
    if comp == Comp::Mysql {
        if let Some(p) = &parked {
            log(
                format!(
                    "datadir: pre-update copy restored; data written since the update kept at {}",
                    p.display()
                ),
                false,
            );
        } else if cur.join("data").is_dir() {
            log(
                "datadir: no safety copy in this backup, the current datadir follows the old build; it may refuse to start".into(),
                true,
            );
        }
    }
    if comp == Comp::Apache || comp == Comp::Php {
        patch_compat(basedir, log);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(name: &str, httpd: &str, old: Option<(&str, &str)>) -> PathBuf {
        let base = std::env::temp_dir().join(format!("ramp-adopt-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join(r"apache\conf\extra")).unwrap();
        fs::write(base.join(r"apache\conf\httpd.conf"), httpd).unwrap();
        if let Some((file, body)) = old {
            fs::write(base.join(r"apache\conf\extra").join(file), body).unwrap();
        }
        base
    }

    const PHP: &str = "LoadModule php_module \"c:/x/php/php8apache2_4.dll\"\n";

    #[test]
    fn php_states_label_the_branches() {
        let json = r#"{"8":{"8.5":{"state":"stable","initial_release":"2025-11-20T00:00:00+00:00","active_support_end":"2027-12-31T00:00:00+00:00","security_support_end":"2029-12-31T00:00:00+00:00"},
            "8.2":{"state":"security","active_support_end":"2024-12-31T00:00:00+00:00","security_support_end":"2026-12-31T00:00:00+00:00"},
            "8.1":{"state":"eol","active_support_end":"2023-11-25T00:00:00+00:00","security_support_end":"2025-12-31T00:00:00+00:00"}},
            "7":{"7.4":{"state":"eol","security_support_end":"2022-11-28T00:00:00+00:00"}}}"#;
        let s = parse_php_states(json).unwrap();
        assert_eq!(s.len(), 4);
        assert_eq!(
            php_branch_label(&s["8.5"]),
            ("Active".into(), "active until 2027-12-31, security until 2029-12-31".into())
        );
        assert_eq!(
            php_branch_label(&s["8.2"]),
            ("Security".into(), "security fixes only, until 2026-12-31".into())
        );
        assert_eq!(php_branch_label(&s["8.1"]).0, "EOL");
    }

    #[test]
    fn mariadb_eol_dates_compare_as_text() {
        assert!(eol_passed("2026-07-06", "2026-11-07"));
        assert!(eol_passed("2026-11-07", "2026-11-07"));
        assert!(!eol_passed("2028-02-16", "2026-11-07"));
        assert!(!eol_passed("", "2026-11-07"));
    }

    #[test]
    fn apache_lounge_build_dates() {
        assert_eq!(
            apachelounge_build_date("httpd-2.4.66-251206-win64-VS17.zip").as_deref(),
            Some("2025-12-06")
        );
        assert_eq!(apachelounge_build_date("httpd-2.4.66-win64-VS17.zip"), None);
    }

    #[test]
    fn the_file_that_loads_php_is_adopted() {
        let httpd = "#Include \"conf/extra/httpd-legacy.conf\"\r\nInclude conf/extra/httpd-ssl.conf\r\nInclude \"conf/extra/httpd-legacy.conf\"\r\n";
        let base = tree("ok", httpd, Some(("httpd-legacy.conf", PHP)));
        fs::write(base.join(r"apache\conf\extra\httpd-ssl.conf"), "Listen 443\n").unwrap();
        let mut lines = Vec::new();
        adopt_php_conf(&base, &mut |l, _| lines.push(l));
        assert_eq!(fs::read_to_string(base.join(PHP_CONF)).unwrap(), PHP);
        assert!(!base.join(r"apache\conf\extra\httpd-legacy.conf").exists());
        assert_eq!(
            fs::read_to_string(base.join(r"apache\conf\httpd.conf")).unwrap(),
            "#Include \"conf/extra/httpd-legacy.conf\"\r\nInclude conf/extra/httpd-ssl.conf\r\nInclude \"conf/extra/httpd-ramp.conf\"\r\n"
        );
        assert_eq!(lines.len(), 1, "{lines:?}");
        // Done once: a second pass changes nothing.
        lines.clear();
        adopt_php_conf(&base, &mut |l, _| lines.push(l));
        assert!(lines.is_empty(), "{lines:?}");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn an_include_into_another_tree_is_left_alone() {
        let other = std::env::temp_dir().join(format!("ramp-adopt-other-{}", std::process::id()));
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("php.conf"), PHP).unwrap();
        let httpd = format!("Include \"{}\"\n", other.join("php.conf").to_string_lossy().replace('\\', "/"));
        let base = tree("far", &httpd, None);
        adopt_php_conf(&base, &mut |_, _| {});
        assert!(other.join("php.conf").is_file());
        assert!(!base.join(PHP_CONF).exists());
        assert_eq!(fs::read_to_string(base.join(r"apache\conf\httpd.conf")).unwrap(), httpd);
        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&other);
    }
}
