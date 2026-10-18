//! First-run bootstrap: fetch and install MariaDB, PHP, Apache and phpMyAdmin
//! into an empty package tree.
//!
//! The update path (update::apply) swaps an existing tree and keeps whatever
//! configuration the user had. On a first run there is nothing to keep: the
//! trees come from the same feeds and are verified the same way (update::
//! fetch_verify), and the configuration is written from RAMP/templates, where
//! the build-machine paths were replaced by placeholders (@ROOT@, @SRVROOT@,
//! @MYSQLDIR@, @APORT@, @PHPMAJOR@, @BLOWFISH@, @MPORT@) that get filled in
//! with the directory the panel happens to run from. Nothing written here
//! hardcodes a path, so the package stays portable wherever it is copied.
//!
//! Everything runs on a worker thread (or under --first-run): it blocks for
//! minutes while archives download and MariaDB seeds its datadir.

use crate::update::{self, Comp, Info, Ver};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const T_HTTPD: &str = include_str!("../templates/httpd.conf");
const T_XAMPP: &str = include_str!("../templates/httpd-xampp.conf");
const T_MYINI: &str = include_str!("../templates/my.ini");
const T_PHPINI: &str = include_str!("../templates/php.ini");
const T_PMA: &str = include_str!("../templates/config.inc.php");
const T_INDEX: &str = include_str!("../templates/index.php");

pub struct Opts {
    pub apache_port: u16,
    pub mysql_port: u16,
    /// MariaDB release line to pin ("" = newest LTS line).
    pub target_line: String,
    /// Start both servers and fetch /phpmyadmin once everything is in place.
    pub verify: bool,
}

/// Server binary the install actually ended up with, so ramp.ini can follow it
/// (MariaDB renamed mysqld.exe to mariadbd.exe in 10.5).
pub struct Boot {
    pub apache_exe: String,
    pub mysql_exe: String,
}

/// Components that are absent or carry no readable version.
pub fn missing(basedir: &Path) -> Vec<Comp> {
    Comp::all()
        .into_iter()
        .filter(|c| update::installed_opt(basedir, *c).is_none())
        .collect()
}

// ---------------------------------------------------------------- templates

/// Path as httpd.conf, my.ini and php.ini like it: forward slashes.
fn fwd(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Path for the Apache SetEnv values, which keep Windows backslashes and are
/// therefore doubled inside the quoted string.
fn doubled(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "\\\\")
}

fn fill(t: &str, map: &[(&str, String)]) -> String {
    let mut s = String::with_capacity(t.len());
    s.push_str(t);
    for (k, v) in map {
        s = s.replace(k, v);
    }
    s
}

fn mkdir(p: &Path) -> Result<(), String> {
    fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn write_text(p: &Path, text: &str) -> Result<(), String> {
    if let Some(d) = p.parent() {
        mkdir(d)?;
    }
    fs::write(p, text).map_err(|e| format!("{}: {e}", p.display()))
}

fn find_in(root: &Path, names: &[&str]) -> Option<PathBuf> {
    names.iter().map(|n| root.join(n)).find(|p| p.is_file())
}

// ------------------------------------------------------------------- helpers

/// Run a tool from the freshly installed tree and capture what it prints.
/// CREATE_NO_WINDOW matters: the panel is a GUI-subsystem binary, so a console
/// would flash up for every mariadb-install-db / mariadb / httpd -t call.
fn run_capture(
    exe: &Path,
    args: &[String],
    cwd: Option<&Path>,
    stdin: Option<&[u8]>,
) -> Result<(i32, String), String> {
    let mut c = Command::new(exe);
    c.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    let mut child = c.spawn().map_err(|e| format!("{}: {e}", exe.display()))?;
    if let Some(s) = stdin {
        if let Some(mut si) = child.stdin.take() {
            si.write_all(s).map_err(|e| format!("writing stdin: {e}"))?;
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let mut txt = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    if !err.trim().is_empty() {
        if !txt.is_empty() {
            txt.push('\n');
        }
        txt.push_str(&err);
    }
    Ok((out.status.code().unwrap_or(-1), txt))
}

/// Compress the tail of a tool's output into one log line.
fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    let keep = &lines[lines.len().saturating_sub(n)..];
    keep.join(" | ")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ------------------------------------------------------------------ install

/// Newest build the feed offers for a component that is not installed yet.
fn pick(comp: Comp, target_line: &str) -> Result<Info, String> {
    let list = match comp {
        Comp::Apache => update::feed_apache(None, true),
        Comp::Mysql => update::feed_mariadb(None, true, target_line),
        Comp::Php => update::feed_php(None, true),
        Comp::Phpmyadmin => update::feed_phpmyadmin(None, true),
    }?;
    list.into_iter()
        .next()
        .ok_or_else(|| format!("no published {} build found", comp.label()))
}

/// Fetch, verify and place one component tree. A directory that exists but
/// holds no working binary is an interrupted install: it gets moved aside into
/// .backup rather than deleted.
fn install_one(
    basedir: &Path,
    info: &Info,
    log: &mut dyn FnMut(String, bool),
    prog: &mut dyn FnMut(u64, u64),
) -> Result<String, String> {
    let comp = info.comp;
    let dst = basedir.join(comp.dir());
    if dst.exists() {
        let aside = basedir
            .join(".backup")
            .join(format!("pre-install-{}", now_secs()));
        mkdir(&aside)?;
        fs::rename(&dst, aside.join(comp.dir())).map_err(|e| {
            format!(
                "{} is in the way and cannot be moved aside: {e}",
                dst.display()
            )
        })?;
        log(
            format!(
                "incomplete {} tree moved aside to {}",
                comp.dir(),
                aside.display()
            ),
            true,
        );
    }
    let (root, marker) = update::fetch_verify(basedir, info, log, prog)?;
    fs::rename(&root, &dst)
        .map_err(|e| format!("move {} -> {}: {e}", root.display(), dst.display()))?;
    update::clean_extract(basedir, comp);
    let exe = marker.rsplit('/').next().unwrap_or(marker).to_string();
    log(
        format!(
            "{} {} installed ({}): {}",
            comp.label(),
            info.available,
            comp.dir(),
            exe
        ),
        false,
    );
    Ok(exe)
}

// ------------------------------------------------------------- configuration

fn write_my_ini(basedir: &Path, port: u16, log: &mut dyn FnMut(String, bool)) -> Result<(), String> {
    let map = [
        ("@MYSQLDIR@", fwd(&basedir.join("mysql"))),
        ("@ROOT@", fwd(basedir)),
        ("@MPORT@", port.to_string()),
    ];
    write_text(&basedir.join("mysql\\bin\\my.ini"), &fill(T_MYINI, &map))?;
    log(format!("my.ini written for this location, port {port}"), false);
    Ok(())
}

fn write_php_ini(basedir: &Path, log: &mut dyn FnMut(String, bool)) -> Result<(), String> {
    let map = [("@ROOT@", fwd(basedir))];
    write_text(&basedir.join("php\\php.ini"), &fill(T_PHPINI, &map))?;
    log("php.ini written (RAMP defaults: 512M memory, 40M uploads, session files in tmp/)".into(), false);
    Ok(())
}

/// Longest common prefix of two paths.
fn lcp(a: &str, b: &str) -> String {
    let mut n = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        if x != y {
            break;
        }
        n += 1;
    }
    a[..n].to_string()
}

/// Absolute paths a configuration file really uses: comment lines are skipped,
/// so a build machine mentioned in prose does not count.
fn drive_paths(txt: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in txt.lines() {
        let l = line.trim_start();
        if l.starts_with('#') {
            continue;
        }
        let b = l.as_bytes();
        let mut i = 0;
        while i + 2 < b.len() {
            let boundary = i == 0 || !(b[i - 1] as char).is_alphanumeric();
            if boundary && (b[i] as char).is_ascii_alphabetic() && b[i + 1] == b':' && b[i + 2] == b'/' {
                let mut j = i + 3;
                while j < b.len() {
                    let c = b[j] as char;
                    if matches!(c, '"' | '\'' | ' ' | '<' | '>' | '#') {
                        break;
                    }
                    j += 1;
                }
                out.push(l[i..j].trim_end_matches('/').to_string());
                i = j;
            } else {
                i += 1;
            }
        }
    }
    out
}

/// The tree an Apache build was made on: `C:/Apache24-64` for an Apache Lounge
/// archive, found by walking the directories those paths live in (strays such
/// as `D:/server.crt` cannot join the majority and are dropped).
fn stock_root(txt: &str) -> Option<String> {
    let parents: Vec<String> = drive_paths(txt)
        .iter()
        .map(|t| match t.rfind('/') {
            Some(p) if p > 2 => t[..p].to_string(),
            _ => t.clone(),
        })
        .filter(|p| p.len() > 3)
        .collect();
    if parents.is_empty() {
        return None;
    }
    let mut best = parents[0].clone();
    let mut best_n = 1usize;
    for p in &parents {
        let n = parents.iter().filter(|q| *q == p).count();
        if n > best_n {
            best = p.clone();
            best_n = n;
        }
    }
    for p in &parents {
        let c = lcp(&best, p);
        if c.len() > 3 {
            best = c;
        }
    }
    while best.ends_with('/') {
        best.pop();
    }
    if best.len() > 3 {
        Some(best)
    } else {
        None
    }
}

/// True when a configuration file this installer owns still names a location
/// outside `root` (lowercase, forward slashes): the tree was copied or moved.
fn refs_outside(txt: &str, root: &str) -> bool {
    drive_paths(txt)
        .iter()
        .any(|d| !d.to_lowercase().starts_with(root))
}

fn outside_root(basedir: &Path, rel: &str) -> bool {
    let root = fwd(basedir).to_lowercase();
    fs::read_to_string(basedir.join(rel))
        .map(|t| refs_outside(&t, &root))
        .unwrap_or(false)
}

const VHOSTS_NOTE: &str = "# RAMP\n# The virtual hosts that ship with an Apache build point at the machine\n# that built it, and a _default_:80 host there would shadow this\n# installation. httpd.conf already sets DocumentRoot, the /phpmyadmin\n# alias and the port, so add your own hosts here.\n";

/// Re-anchor the conf/extra files the Apache archive brought along: they name
/// the build machine, which no portable tree can honour. Only untouched stock
/// files are touched, never the RAMP files this installer writes.
fn reanchor_extras(basedir: &Path, log: &mut dyn FnMut(String, bool)) {
    let extra = basedir.join("apache\\conf\\extra");
    let srvroot = fwd(&basedir.join("apache"));
    let Ok(rd) = fs::read_dir(&extra) else { return };
    let mut names: Vec<String> = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if !name.ends_with(".conf") || name == "httpd-xampp.conf" {
            continue;
        }
        names.push(name);
    }
    names.sort();
    for name in names {
        let p = extra.join(&name);
        let Ok(txt) = fs::read_to_string(&p) else { continue };
        if txt.lines().any(|l| !l.trim_start().starts_with('#') && l.contains("dummy-host")) {
            if write_text(&p, VHOSTS_NOTE).is_ok() {
                log(format!("conf/extra/{name}: the build machine's dummy virtual hosts removed"), false);
            }
            continue;
        }
        let Some(root) = stock_root(&txt) else { continue };
        if root.eq_ignore_ascii_case(&srvroot) {
            continue;
        }
        let out = txt.replace(&root, &srvroot);
        if out == txt {
            continue;
        }
        if write_text(&p, &out).is_ok() {
            log(format!("conf/extra/{name}: {root} re-anchored onto this installation"), false);
        }
    }

    // Apache Lounge ships SSLCertificateFile "/server.crt": a leading slash on
    // Windows means "root of the current drive". Point at our own certificate.
    let ssl = extra.join("httpd-ssl.conf");
    let Ok(txt) = fs::read_to_string(&ssl) else { return };
    let mut out = String::new();
    let mut fixed = 0usize;
    for line in txt.lines() {
        let tr = line.trim_start();
        let directive = if tr.starts_with("SSLCertificateFile") {
            "conf\\ssl.crt\\server.crt"
        } else if tr.starts_with("SSLCertificateKeyFile") {
            "conf\\ssl.key\\server.key"
        } else {
            ""
        };
        if directive.is_empty() {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let value = tr.split_whitespace().skip(1).collect::<Vec<_>>().join(" ").trim_matches('"').to_string();
        let resolved = if value.len() > 2 && value.as_bytes()[1] == b':' {
            PathBuf::from(&value)
        } else {
            basedir.join("apache").join(&value)
        };
        if resolved.is_file() {
            out.push_str(line);
        } else {
            out.push_str(&format!(
                "{} \"{}\"",
                tr.split_whitespace().next().unwrap_or("SSLCertificateFile"),
                directive.replace('\\', "/")
            ));
            fixed += 1;
        }
        out.push('\n');
    }
    if fixed > 0 && write_text(&ssl, &out).is_ok() {
        log(format!("conf/extra/httpd-ssl.conf: {fixed} certificate path(s) pointed at this installation"), false);
    }
}

/// A httpd.conf that `Include`s a conf/extra file the tree does not have can
/// only ever be rejected: it came from another build (XAMPP ships httpd-proxy.conf
/// and httpd-ajp.conf, Apache Lounge does not) or from a half-finished install.
fn conf_references_missing(basedir: &Path) -> bool {
    let Ok(txt) = fs::read_to_string(basedir.join("apache\\conf\\httpd.conf")) else {
        return true;
    };
    for line in txt.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        let Some(rest) = l
            .strip_prefix("IncludeOptional")
            .or_else(|| l.strip_prefix("Include"))
        else {
            continue;
        };
        let p = rest.trim().trim_matches('"').trim().replace('/', "\\");
        if p.is_empty() || p.contains('$') || p.contains('*') || p.contains('?') || p.contains(' ') {
            continue;
        }
        if !basedir.join("apache").join(&p).exists() {
            return true;
        }
    }
    false
}

fn write_apache_conf(
    basedir: &Path,
    port: u16,
    php_major: u32,
    log: &mut dyn FnMut(String, bool),
) -> Result<(), String> {
    let map = [
        ("@SRVROOT@", fwd(&basedir.join("apache"))),
        ("@ROOT@", fwd(basedir)),
        ("@ROOTBS@", doubled(basedir)),
        ("@APORT@", port.to_string()),
        ("@PHPMAJOR@", php_major.to_string()),
    ];
    // The Apache archive ships a conf/httpd.conf with c:/Apache24 baked in. A
    // first install replaces it: DocumentRoot must land outside the Apache tree,
    // at <package>/htdocs, and mod_php has to be wired up.
    write_text(
        &basedir.join("apache\\conf\\httpd.conf"),
        &fill(T_HTTPD, &map),
    )?;
    write_text(
        &basedir.join("apache\\conf\\extra\\httpd-xampp.conf"),
        &fill(T_XAMPP, &map),
    )?;
    log(
        format!(
            "httpd.conf + conf/extra/httpd-xampp.conf written for this location, listening on {port}"
        ),
        false,
    );
    Ok(())
}

/// 48-char cookie secret, asked for from PHP's own CSPRNG: the call doubles as
/// proof that the freshly installed PHP really runs.
fn pma_secret(basedir: &Path, log: &mut dyn FnMut(String, bool)) -> String {
    let php = basedir.join("php\\php.exe");
    if php.is_file() {
        let args = [
            "-r".to_string(),
            "echo bin2hex(random_bytes(24));".to_string(),
        ];
        if let Ok((0, out)) = run_capture(&php, &args, php.parent(), None) {
            let hex: String = out.trim().chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if hex.len() == 48 {
                return hex;
            }
        }
        log(
            "cookie secret: PHP produced nothing, falling back to a clock-seeded value".into(),
            true,
        );
    }
    // Not cryptographic, but per-install and never published.
    let mut x = (now_secs() as u64) ^ ((std::process::id() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let digits = b"0123456789abcdef";
    let mut s = String::new();
    while s.len() < 48 {
        x ^= x >> 12;
        x = x.wrapping_mul(0x2545_f491_4f6c_dd1d);
        x ^= x >> 32;
        for b in x.to_be_bytes() {
            s.push(digits[(b >> 4) as usize] as char);
            s.push(digits[(b & 15) as usize] as char);
        }
    }
    s[..48].to_string()
}

fn write_pma_conf(basedir: &Path, port: u16, log: &mut dyn FnMut(String, bool)) -> Result<(), String> {
    let map = [
        ("@BLOWFISH@", pma_secret(basedir, log)),
        ("@MPORT@", port.to_string()),
    ];
    write_text(
        &basedir.join("phpMyAdmin\\config.inc.php"),
        &fill(T_PMA, &map),
    )?;
    for d in ["phpMyAdmin\\tmp", "phpMyAdmin\\upload_tmp"] {
        mkdir(&basedir.join(d))?;
    }
    log("config.inc.php written: root over TCP with no password yet, random cookie secret".into(), false);
    Ok(())
}

// ----------------------------------------------------------------- database

/// A datadir only counts once the bootstrap system tables are in it.
fn datadir_ready(basedir: &Path) -> bool {
    basedir.join("mysql\\data\\mysql").is_dir()
}

/// Seed the datadir with the build that was installed seconds ago.
fn init_datadir(basedir: &Path, port: u16, log: &mut dyn FnMut(String, bool)) -> Result<(), String> {
    let bin = basedir.join("mysql\\bin");
    let Some(tool) = find_in(
        basedir,
        &["mysql\\bin\\mariadb-install-db.exe", "mysql\\bin\\mysql_install_db.exe"],
    ) else {
        return Err("the MariaDB tree has no mariadb-install-db: the datadir cannot be created".into());
    };
    let data = basedir.join("mysql\\data");
    let empty = match fs::read_dir(&data) {
        Err(_) => true,
        Ok(mut rd) => rd.next().is_none(),
    };
    if !empty {
        log("mysql/data already holds a datadir, left untouched".into(), false);
        return Ok(());
    }
    // The Windows mariadb-install-db is the old mysql_install_db: it takes its
    // own switch set and rejects --defaults-file outright.
    let args = [
        format!("--datadir={}", data.to_string_lossy()),
        format!("--port={port}"),
    ];
    log("creating the MariaDB data directory...".into(), false);
    let (code, out) = run_capture(&tool, &args, Some(&bin), None)?;
    if code != 0 {
        return Err(format!("mariadb-install-db failed ({code}): {}", tail(&out, 6)));
    }
    log("datadir created: root@localhost with an empty password".into(), false);
    Ok(())
}

/// Control user + configuration storage tables, against a running server.
fn seed_pmadb(basedir: &Path, port: u16, log: &mut dyn FnMut(String, bool)) -> Result<(), String> {
    let bin = basedir.join("mysql\\bin");
    let Some(cli) = find_in(basedir, &["mysql\\bin\\mariadb.exe", "mysql\\bin\\mysql.exe"]) else {
        log("no mariadb client in the tree: phpMyAdmin storage setup skipped".into(), true);
        return Ok(());
    };
    let args = [
        "--host=127.0.0.1".to_string(),
        format!("--port={port}"),
        "--user=root".to_string(),
    ];
    let user_sql = "CREATE USER IF NOT EXISTS 'pma'@'localhost' IDENTIFIED BY '';\n\
                    GRANT SELECT, INSERT, UPDATE, DELETE ON `phpmyadmin`.* TO 'pma'@'localhost';\n\
                    FLUSH PRIVILEGES;\n";
    let (c1, o1) = run_capture(&cli, &args, Some(&bin), Some(user_sql.as_bytes()))?;
    if c1 != 0 {
        return Err(format!("cannot create the phpMyAdmin control user: {}", tail(&o1, 6)));
    }
    log("control user 'pma' created".into(), false);
    let f = basedir.join("phpMyAdmin\\sql\\create_tables.sql");
    if !f.is_file() {
        log("phpMyAdmin/sql/create_tables.sql is missing: advanced features stay off".into(), true);
        return Ok(());
    }
    let sql = fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?;
    let (c2, o2) = run_capture(&cli, &args, Some(&bin), Some(&sql))?;
    if c2 != 0 {
        return Err(format!("create_tables.sql failed: {}", tail(&o2, 6)));
    }
    log("phpMyAdmin configuration storage (pmadb) imported".into(), false);
    Ok(())
}

/// Ask the new httpd to parse the new configuration. This also loads mod_php,
/// so a PHP build whose runtime DLLs are missing fails here instead of at the
/// first request.
fn check_apache(basedir: &Path, log: &mut dyn FnMut(String, bool)) -> Result<(), String> {
    let httpd = basedir.join("apache\\bin\\httpd.exe");
    if !httpd.is_file() {
        return Err("apache/bin/httpd.exe is missing".into());
    }
    let conf = basedir.join("apache\\conf\\httpd.conf");
    let args = [
        "-t".to_string(),
        "-f".to_string(),
        conf.to_string_lossy().into_owned(),
    ];
    let (code, out) = run_capture(&httpd, &args, Some(basedir), None)?;
    let msg = tail(&out, 8);
    if code != 0 {
        return Err(format!("the new configuration was rejected by httpd -t ({code}): {msg}"));
    }
    log(format!("apache configuration check: {msg}"), false);
    Ok(())
}

/// End-to-end proof: boot both servers and fetch the phpMyAdmin start page.
fn verify_running(
    basedir: &Path,
    o: &Opts,
    apache_exe: &str,
    mysql_exe: &str,
    log: &mut dyn FnMut(String, bool),
) -> Result<(), String> {
    use crate::{http::http_get, start_module_blocking, stop_module_blocking};
    log("verification: starting MariaDB and Apache".into(), false);
    let r = (|| -> Result<(), String> {
        start_module_blocking(basedir, "MariaDB", mysql_exe)?;
        start_module_blocking(basedir, "Apache", apache_exe)?;
        let url = format!("http://127.0.0.1:{}/phpmyadmin/", o.apache_port);
        let resp = http_get(&url).map_err(|e| format!("{url}: {e}"))?;
        if resp.status >= 400 {
            return Err(format!("{url} answered HTTP {}", resp.status));
        }
        log(
            format!(
                "verification: /phpmyadmin answered HTTP {} ({} bytes)",
                resp.status,
                resp.body.len()
            ),
            false,
        );
        Ok(())
    })();
    // Only what this function started is taken down again; the panel will not
    // have had a chance to start anything else while the worker was busy.
    stop_module_blocking(&[o.apache_port, o.mysql_port]);
    r
}

/// True when nothing else owns the port. Bootstrap never touches a port it did
/// not open itself: killing a server the user started from another tree would
/// be worse than skipping the check.
fn port_free(port: u16) -> bool {
    // 2 == MIB_TCP_STATE_LISTEN: TIME_WAIT sockets left by the seeding client
    // are not a port conflict.
    !crate::netstat::tcp_table()
        .iter()
        .any(|e| e.local == port && e.state == 2)
}

// ---------------------------------------------------------------- top level

/// True when an installed tree carries configuration that cannot work here:
/// paths from another location (a copied or moved package), or includes the
/// Apache build does not ship. The panel repairs that on startup.
pub fn needs_repair(basedir: &Path) -> bool {
    let apache = update::installed_opt(basedir, Comp::Apache).is_some()
        && (outside_root(basedir, "apache\\conf\\httpd.conf")
            || outside_root(basedir, "apache\\conf\\extra\\httpd-xampp.conf")
            || conf_references_missing(basedir));
    let mysql =
        update::installed_opt(basedir, Comp::Mysql).is_some() && outside_root(basedir, "mysql\\bin\\my.ini");
    apache || mysql
}

/// Install every component that is still missing, in dependency order, then
/// write the portable configuration, seed the database, create the https
/// certificate and syntax-check Apache.
pub fn bootstrap(
    basedir: &Path,
    o: &Opts,
    log: &mut dyn FnMut(String, bool),
    prog: &mut dyn FnMut(u64, u64),
) -> Result<Boot, String> {
    let miss = missing(basedir);
    if miss.is_empty() {
        log("every component is installed: checking configuration only".into(), false);
    } else {
        log(
            format!(
                "first run: installing {}",
                miss.iter().map(|c| c.label()).collect::<Vec<_>>().join(", ")
            ),
            false,
        );
    }
    let mut boot = Boot {
        apache_exe: "httpd.exe".into(),
        mysql_exe: "mariadbd.exe".into(),
    };

    for comp in [Comp::Mysql, Comp::Php, Comp::Apache, Comp::Phpmyadmin] {
        if !miss.contains(&comp) {
            continue;
        }
        let info = pick(comp, &o.target_line)?;
        log(
            format!(
                "{}: picking {} ({}, {})",
                comp.label(),
                info.available,
                info.file,
                if info.size > 0 {
                    format!("{} MB", (info.size + 1_048_575) / 1_048_576)
                } else {
                    "size ?".into()
                }
            ),
            false,
        );
        let exe = install_one(basedir, &info, log, prog)?;
        match comp {
            Comp::Mysql => {
                boot.mysql_exe = exe;
                mkdir(&basedir.join("tmp"))?;
                write_my_ini(basedir, o.mysql_port, log)?;
                init_datadir(basedir, o.mysql_port, log)?;
            }
            Comp::Php => {
                write_php_ini(basedir, log)?;
                mkdir(&basedir.join("php\\logs"))?;
            }
            Comp::Apache => {
                boot.apache_exe = exe;
                let major = Ver::parse(&info.available).map(|v| v.0[0]).unwrap_or(8);
                write_apache_conf(basedir, o.apache_port, major, log)?;
                for d in ["apache\\logs", "cgi-bin", "htdocs"] {
                    mkdir(&basedir.join(d))?;
                }
                // The configuration ships with https enabled, so it needs a
                // certificate the moment it is written.
                if let Err(e) = crate::regenerate_server_cert(basedir, log) {
                    log(format!("no certificate yet: {e}"), true);
                }
            }
            Comp::Phpmyadmin => {
                write_pma_conf(basedir, o.mysql_port, log)?;
            }
        }
    }

    // A tree that survived an interrupted run still owes its configuration,
    // its datadir or its certificate: finish that part of the job.
    if update::installed_opt(basedir, Comp::Mysql).is_some() {
        let myini = "mysql\\bin\\my.ini";
        let moved = basedir.join(myini).is_file() && outside_root(basedir, myini);
        if !basedir.join(myini).is_file() || moved {
            if moved {
                log("my.ini still named another installation: rewritten".into(), true);
            }
            write_my_ini(basedir, o.mysql_port, log)?;
        }
        if !datadir_ready(basedir) {
            init_datadir(basedir, o.mysql_port, log)?;
        }
        if find_in(basedir, &["mysql\\bin\\mariadbd.exe"]).is_some() {
            boot.mysql_exe = "mariadbd.exe".into();
        } else if find_in(basedir, &["mysql\\bin\\mysqld.exe"]).is_some() {
            boot.mysql_exe = "mysqld.exe".into();
        }
    }
    if update::installed_opt(basedir, Comp::Php).is_some() && !basedir.join("php\\php.ini").is_file() {
        write_php_ini(basedir, log)?;
        mkdir(&basedir.join("php\\logs"))?;
    }
    if update::installed_opt(basedir, Comp::Apache).is_some() {
        boot.apache_exe = "httpd.exe".into();
        for d in ["apache\\logs", "cgi-bin", "htdocs"] {
            mkdir(&basedir.join(d))?;
        }
        let broken_includes =
            basedir.join("apache\\conf\\extra\\httpd-xampp.conf").is_file() && conf_references_missing(basedir);
        let moved = basedir.join("apache\\conf\\extra\\httpd-xampp.conf").is_file()
            && (outside_root(basedir, "apache\\conf\\httpd.conf")
                || outside_root(basedir, "apache\\conf\\extra\\httpd-xampp.conf"));
        if !basedir.join("apache\\conf\\extra\\httpd-xampp.conf").is_file() || broken_includes || moved {
            if broken_includes {
                log("httpd.conf includes files this Apache build does not ship: rewriting it".into(), true);
            }
            if moved {
                log("httpd.conf still named another installation: rewritten".into(), true);
            }
            let major = update::installed_opt(basedir, Comp::Php)
                .map(|v| v.0[0])
                .unwrap_or(8);
            write_apache_conf(basedir, o.apache_port, major, log)?;
        }
        // The configuration ships with https enabled, so it needs a certificate.
        if !basedir.join("apache\\conf\\ssl.crt\\server.crt").is_file() {
            if let Err(e) = crate::regenerate_server_cert(basedir, log) {
                log(format!("no certificate yet: {e}"), true);
            }
        }
    }
    if update::installed_opt(basedir, Comp::Phpmyadmin).is_some()
        && !basedir.join("phpMyAdmin\\config.inc.php").is_file()
    {
        write_pma_conf(basedir, o.mysql_port, log)?;
    }

    let doc = basedir.join("htdocs\\index.php");
    if !doc.is_file() {
        write_text(&doc, T_INDEX)?;
        log("htdocs/index.php written (RAMP status page)".into(), false);
    }
    mkdir(&basedir.join("tmp"))?;
    reanchor_extras(basedir, log);
    update::patch_compat(basedir, log);
    if missing(basedir).is_empty() {
        check_apache(basedir, log)?;
    }

    // phpMyAdmin's storage needs a live server, so start MariaDB, seed it, and
    // hand the port back. mysql/data/phpmyadmin is the sign the job is done.
    let seeded = basedir.join("mysql\\data\\phpmyadmin").is_dir();
    if !seeded
        && update::installed_opt(basedir, Comp::Phpmyadmin).is_some()
        && update::installed_opt(basedir, Comp::Mysql).is_some()
    {
        if !port_free(o.mysql_port) {
            log(
                format!(
                    "port {} is already in use, so MariaDB cannot be started to seed phpMyAdmin: start it yourself and import phpMyAdmin/sql/create_tables.sql",
                    o.mysql_port
                ),
                true,
            );
        } else {
            // Seeding needs a live server: start MariaDB, seed it, hand the port back.
            crate::start_module_blocking(basedir, "MariaDB", &boot.mysql_exe)
                .map_err(|e| format!("cannot start MariaDB to seed phpMyAdmin: {e}"))?;
            let r = seed_pmadb(basedir, o.mysql_port, log);
            crate::stop_module_blocking(&[o.mysql_port]);
            r?;
        }
    }

    if o.verify {
        if !port_free(o.apache_port) || !port_free(o.mysql_port) {
            log(
                format!(
                    "verification skipped: port {} or {} is already in use",
                    o.apache_port, o.mysql_port
                ),
                true,
            );
        } else {
            verify_running(basedir, o, &boot.apache_exe, &boot.mysql_exe, log)?;
        }
    }
    log("installation complete".into(), false);
    Ok(boot)
}
