mod config;
mod http;
mod netstat;
mod procs;
mod update;

use slint::{
    CloseRequestResponse, ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
};
use windows::Win32::System::SystemInformation::GetLocalTime;
use windows::Win32::System::Threading::{
    CreateProcessW, OpenProcess, TerminateProcess, CREATE_NEW_CONSOLE, NORMAL_PRIORITY_CLASS,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_TERMINATE, STARTF_USESHOWWINDOW,
    STARTUPINFOW,
};
use windows::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::{SHOW_WINDOW_CMD, SW_HIDE, SW_SHOW};

slint::include_modules!();

type AppRc = Rc<RefCell<App>>;

const MAX_LOG_LINES: usize = 500;

// Delphi: cRunningColor=$C8FFC8, cPartialColor=clYellow, cStoppedColor=clBtnFace,
// cErrorColor=clRed. Stopped is re-tuned for the dark theme.
const BG_RUNNING: (u8, u8, u8) = (200, 255, 200);
const BG_PARTIAL: (u8, u8, u8) = (255, 213, 74);
const BG_STOPPED: (u8, u8, u8) = (58, 63, 75);
const BG_ERROR: (u8, u8, u8) = (255, 77, 77);
const FG_RUNNING: (u8, u8, u8) = (18, 88, 18);
const FG_PARTIAL: (u8, u8, u8) = (74, 54, 0);
const FG_STOPPED: (u8, u8, u8) = (154, 160, 170);
const FG_ERROR: (u8, u8, u8) = (40, 8, 8);

#[derive(Clone, Copy, PartialEq)]
enum LogType {
    Default,
    Info,
    Error,
    Debug,
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Idle,
    Starting,
    Stopping,
}

struct Module {
    name: &'static str,
    binary: String, // lowercase, e.g. "httpd.exe"
    check_ports: Vec<u16>,
    expect_pids: usize, // Apache: master + child = 2, MySQL: 1
    pids: Vec<u32>,
    running: bool,
    error: bool,
    old_running: Option<bool>, // None == Delphi's oldIsRunningByte = 2 (unknown)
    old_pid_count: usize,
    phase: Phase,
}

struct App {
    basedir: PathBuf,
    ini_path: PathBuf,
    log_path: PathBuf,
    cfg: config::Config,
    modules: Vec<Module>,
    tcp: Vec<netstat::TcpEntry>,
    names: HashMap<u32, String>,
    log_file: Vec<String>,
    log_dirty: bool,
    file_win: Option<Rc<FileWindow>>,
    file_model: Rc<VecModel<FileRow>>,
    settings_win: Option<Rc<ConfigWindow>>,
    upd_win: Option<Rc<UpdateWindow>>,
    about_win: Option<Rc<AboutWindow>>,
    upd_model: Rc<VecModel<UpdateInfo>>,
    upd_info: Vec<Vec<update::Info>>,
    upd_sel: Vec<usize>,
    upd_comps: Vec<update::Comp>,
    upd_rx: Option<std::sync::mpsc::Receiver<UpdMsg>>,
    upd_busy: bool,
    closing: bool,
}

#[derive(Clone)]
struct Ui {
    main: Rc<MainWindow>,
    log_model: Rc<VecModel<LogLine>>,
    mod_model: Rc<VecModel<ModuleInfo>>,
}

fn brush(c: (u8, u8, u8)) -> slint::Brush {
    slint::Color::from_rgb_u8(c.0, c.1, c.2).into()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn local_time() -> String {
    let st = unsafe { GetLocalTime() };
    format!("{:02}:{:02}:{:02}", st.wHour, st.wMinute, st.wSecond)
}

fn reg_sz(subkey: &str, value: &str) -> Option<String> {
    unsafe {
        let sub = wide(subkey);
        let val = wide(value);
        let mut buf = [0u16; 512];
        let mut size = (buf.len() * 2) as u32;
        let res = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub.as_ptr()),
            PCWSTR(val.as_ptr()),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            None,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut size),
        );
        if res.0 != 0 || size < 4 {
            return None;
        }
        let chars = (size as usize / 2) - 1;
        Some(String::from_utf16_lossy(&buf[..chars.min(buf.len())]))
    }
}

fn windows_version() -> String {
    const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let product = reg_sz(KEY, "ProductName").unwrap_or_else(|| "Windows".into());
    let display = reg_sz(KEY, "DisplayVersion")
        .or_else(|| reg_sz(KEY, "ReleaseId"))
        .unwrap_or_default();
    let build = reg_sz(KEY, "CurrentBuildNumber").unwrap_or_default();
    let bitness = if cfg!(target_pointer_width = "64") {
        "64-bit"
    } else {
        "32-bit"
    };
    let mut s = product;
    if !display.is_empty() {
        s.push(' ');
        s.push_str(&display);
    }
    if !build.is_empty() {
        s.push_str(" (build ");
        s.push_str(&build);
        s.push(')');
    }
    format!("{s} {bitness}")
}

fn detect_basedir() -> PathBuf {
    match std::env::var("XAMPP_BASEDIR") {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from(".")),
    }
}

fn exe_stem() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.file_stem().map(|s| s.to_string_lossy().to_string()))
        .unwrap_or_else(|| "xampp-rs".into())
}

/// Port of TfMain.TryGuessXamppVersion: first line of readme_de.txt (fallback
/// readme_en.txt) containing "version X.Y.Z" or "... portable X.Y.Z Portable".
fn guess_xampp_version(basedir: &Path) -> String {
    for name in ["readme_de.txt", "readme_en.txt"] {
        let Ok(text) = std::fs::read_to_string(basedir.join(name)) else {
            continue;
        };
        let first = text.lines().next().unwrap_or("").to_lowercase();
        if let Some(p) = first.find("version") {
            let rest = &first[(p + 8).min(first.len())..];
            if let Some(sp) = rest.find(' ') {
                let v = rest[..sp].trim();
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        } else if let Some(p) = first.find("portable") {
            let rest = &first[(p + 9).min(first.len())..];
            if let Some(sp) = rest.find(' ') {
                let v = rest[..sp].trim();
                if !v.is_empty() {
                    return format!("{v} Portable");
                }
            }
        }
    }
    "???".into()
}

// ---------------------------------------------------------------- process helpers

unsafe fn create_process(
    cmdline: &str,
    basedir: &Path,
    show: SHOW_WINDOW_CMD,
    env_block: Option<&[u16]>,
) -> Result<u32, String> {
    let mut raw = wide(cmdline);
    let dir = wide(&basedir.to_string_lossy());
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESHOWWINDOW,
        wShowWindow: show.0 as u16,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    let flags: PROCESS_CREATION_FLAGS = CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS;
    let res = CreateProcessW(
        PCWSTR::null(),
        Some(PWSTR(raw.as_mut_ptr())),
        None,
        None,
        false,
        flags,
        env_block.map(|e| e.as_ptr() as *const core::ffi::c_void),
        PCWSTR(dir.as_ptr()),
        &si,
        &mut pi,
    );
    match res {
        Ok(()) => {
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            Ok(pi.dwProcessId)
        }
        Err(e) => Err(format!("{:#010x} - {}", e.code().0 as u32, e.message())),
    }
}

fn run_process(cmdline: &str, basedir: &Path, show: SHOW_WINDOW_CMD) -> Result<u32, String> {
    unsafe { create_process(cmdline, basedir, show, None) }
}

/// mod_php needs two things in the httpd.exe process environment, both toggled
/// around the spawn (CreateProcessW(NULL env) inherits this process's env;
/// building a custom env block was rejected with 0x80070057):
///  - PATH contains <basedir>\php so extensions in php\ext resolve their sibling
///    DLLs (libssh2, icu, ...) from the php root;
///  - PHPRC points at <basedir>\php so mod_php loads php.ini at module init.
///    Apache's `SetEnv PHPRC` only lands in the request environment, which PHP
///    has already finished reading by then; `PHPINIDir` would fix it but crashes
///    mod_php >= 8.5 (worker 0xC0000005). Without an ini, phpMyAdmin loses
///    mysqli and every `extension=` line.
fn with_php_env<T>(basedir: &Path, f: impl FnOnce() -> T) -> T {
    // Keep the apache\bin php.ini mirror current for Apache launched outside
    // the panel (double-clicked httpd.exe has no PHPRC and falls back to its
    // own directory).
    update::ensure_ini_fallback(basedir, &mut |_l, _warn| {});
    let old_path = std::env::var("PATH").unwrap_or_default();
    let old_phprc = std::env::var_os("PHPRC");
    let php = basedir.join("php").to_string_lossy().into_owned();
    std::env::set_var("PATH", format!("{php};{old_path}"));
    std::env::set_var("PHPRC", &php);
    let out = f();
    std::env::set_var("PATH", old_path);
    match old_phprc {
        Some(v) => std::env::set_var("PHPRC", v),
        None => std::env::remove_var("PHPRC"),
    }
    out
}

/// Blocking start used by the updater: same command lines as start_module(), but
/// it waits until the process really owns a listening socket instead of leaving
/// that to the 250 ms timer. A swap is only trustworthy once the new build has
/// been shown to boot.
fn start_module_blocking(basedir: &Path, name: &str, binary: &str) -> Result<(), String> {
    let cmdline = if name == "Apache" {
        format!(
            "\"{}\"",
            basedir
                .join(format!("apache\\bin\\{binary}"))
                .to_string_lossy()
        )
    } else {
        let exe = basedir.join(format!("mysql\\bin\\{binary}"));
        let ini = basedir.join("mysql\\bin\\my.ini");
        format!(
            "\"{}\" --defaults-file=\"{}\" --standalone",
            exe.to_string_lossy(),
            ini.to_string_lossy()
        )
    };
    let spawn = || run_process(&cmdline, basedir, SW_HIDE);
    let pid = if name == "Apache" { with_php_env(basedir, spawn) } else { spawn() }?;
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if netstat::tcp_table().iter().any(|e| e.pid == pid) {
            return Ok(());
        }
        if procs::process_path(pid).is_empty() {
            return Err(format!(
                "{name} exited during startup (check its error log)"
            ));
        }
    }
    terminate_pid(pid);
    Err(format!(
        "{name} opened no listening socket within 30s (pid {pid})"
    ))
}

/// Blocking stop used by the updater: kills whatever holds the module's ports and
/// waits for those ports to be free. Required before a swap, since on Windows a
/// running exe cannot be moved out of the way.
fn stop_module_blocking(ports: &[u16]) -> Vec<u32> {
    let tab = netstat::tcp_table();
    let mut killed = Vec::new();
    for p in ports {
        if let Some(e) = tab.iter().find(|e| e.local == *p) {
            if terminate_pid(e.pid) {
                killed.push(e.pid);
            }
        }
    }
    if !killed.is_empty() {
        for _ in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let tab = netstat::tcp_table();
            if ports.iter().all(|p| !tab.iter().any(|e| e.local == *p)) {
                break;
            }
        }
    }
    killed
}

// ---------------------------------------------------------------- updater glue

/// Worker -> UI messages. The worker thread never touches a Slint object: the
/// 500 ms timer drains this queue on the UI thread instead.
enum UpdMsg {
    Checked(Vec<(update::Comp, Result<Vec<update::Info>, String>)>),
    Log(String, bool),
    Finished(Result<update::Applied, String>),
    Restored(update::Comp, Result<String, String>),
}

/// MariaDB >= 10.5 refuses "InnoDB: upgrade after a crash". The panel stops
/// servers with TerminateProcess, which leaves the redo log uncheckpointed. So
/// PHP has no daemon of its own: prove a swapped-in build really runs by
/// letting the CLI write a marker file. A tree missing its runtime DLLs or
/// the Visual C++ redist never produces it.
fn smoke_php(basedir: &Path) -> Result<(), String> {
    let php = basedir.join("php\\php.exe");
    if !php.is_file() {
        return Err("php.exe is missing from the build".into());
    }
    let work = basedir.join("tmp\\update");
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let mark = work.join("php_smoke.ok");
    let _ = std::fs::remove_file(&mark);
    let pid = run_process(
        &format!(
            "\"{}\" -r \"file_put_contents('{}', '1');\"",
            php.to_string_lossy(),
            mark.to_string_lossy().replace('\\', "/")
        ),
        basedir,
        SW_HIDE,
    )?;
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if procs::process_path(pid).is_empty() {
            let ok = std::fs::metadata(&mark)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
            let _ = std::fs::remove_file(&mark);
            return if ok {
                Ok(())
            } else {
                Err("the PHP CLI did not run (missing Visual C++ runtime?)".into())
            };
        }
    }
    terminate_pid(pid);
    let _ = std::fs::remove_file(&mark);
    Err("the PHP CLI hung for 30s".into())
}

/// before a MariaDB swap: start the old build, then shut it down cleanly with
/// mysqladmin. Takes seconds, and is the official migration precondition.
fn checkpoint_mysql_datadir(
    basedir: &Path,
    binary: &str,
    port: u16,
    log: &mut dyn FnMut(String, bool),
) -> Result<(), String> {
    let admin = basedir.join("mysql\\bin\\mysqladmin.exe");
    if !admin.is_file() {
        return Err("mysqladmin.exe not found: cannot checkpoint the datadir".into());
    }
    log(
        "checkpointing the datadir with the old build (crash recovery can take a while)...".into(),
        false,
    );
    // The INI name may lag a component update (mysqld -> mariadbd and back);
    // trust the tree that is on disk.
    let real = update::find_exe(&basedir.join("mysql"), update::Comp::Mysql)
        .map(|rel| rel.rsplit('/').next().unwrap_or(rel).to_string())
        .unwrap_or_else(|| binary.to_string());
    let exe = basedir.join(format!("mysql\\bin\\{real}"));
    if !exe.is_file() {
        return Err(format!(
            "no server binary in mysql\\bin (looked for {real})"
        ));
    }
    let ini = basedir.join("mysql\\bin\\my.ini");
    let pid = run_process(
        &format!(
            "\"{}\" --defaults-file=\"{}\" --standalone",
            exe.to_string_lossy(),
            ini.to_string_lossy()
        ),
        basedir,
        SW_HIDE,
    )?;
    let mut up = false;
    for _ in 0..240 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if netstat::tcp_table().iter().any(|e| e.pid == pid) {
            up = true;
            break;
        }
    }
    if !up {
        terminate_pid(pid);
        return Err("the old server opened no listening socket within 120s".into());
    }
    let cmdline = format!(
        "\"{}\" --user=root --protocol=tcp --port={port} shutdown",
        admin.to_string_lossy()
    );
    let _ = run_process(&cmdline, basedir, SW_HIDE)?;
    // The listening socket closes before InnoDB has written its final
    // shutdown checkpoint: wait for the process itself to exit, or the
    // datadir move would race with the old server's last flushes.
    let mut down = false;
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if procs::process_path(pid).is_empty() {
            down = true;
            break;
        }
    }
    if !down {
        terminate_pid(pid);
        return Err("the old server ignored mysqladmin shutdown (root password set?)".into());
    }
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !netstat::tcp_table().iter().any(|e| e.local == port) {
            log(
                "datadir checkpointed: old server stopped cleanly".into(),
                false,
            );
            return Ok(());
        }
    }
    Err("port busy although the old server exited (another process holds it?)".into())
}

/// After a MariaDB major jump the system tables are still the old build's.
/// Called while the smoke test has the new server listening: run the upgrade
/// tool from the new tree (mariadb-upgrade since 10.5, mysql_upgrade before).
fn run_system_upgrade(basedir: &Path, ports: &[u16], log: &mut dyn FnMut(String, bool)) {
    let tool = ["mariadb-upgrade.exe", "mysql_upgrade.exe"]
        .iter()
        .map(|n| basedir.join(format!("mysql\\bin\\{n}")))
        .find(|p| p.is_file());
    let Some(tool) = tool else {
        log(
            "no upgrade tool in the new build: run it manually".into(),
            true,
        );
        return;
    };
    let port = ports.first().copied().unwrap_or(3306);
    let name = tool
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    log(
        format!("migrating the system tables ({name})...").into(),
        false,
    );
    let cmdline = format!(
        "\"{}\" --user=root --protocol=tcp --port={port}",
        tool.to_string_lossy()
    );
    match run_process(&cmdline, basedir, SW_HIDE) {
        Ok(upid) => {
            for _ in 0..240 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if procs::process_path(upid).is_empty() {
                    log("system tables migrated".into(), false);
                    return;
                }
            }
            log(
                format!("{name} still running after 120s: check the datadir").into(),
                true,
            );
        }
        Err(e) => log(format!("could not run {name}: {e}").into(), true),
    }
}

/// True when the fresh Apache error log shows the new OpenSSL refusing the
/// current certificate (XAMPP ships a 1024-bit one, rejected since 3.5).
fn apache_cert_rejected(basedir: &Path) -> bool {
    let p = basedir.join("apache\\logs\\error.log");
    match std::fs::read_to_string(&p) {
        Ok(s) => {
            let rev: String = s.chars().rev().take(6000).collect();
            let tail: String = rev.chars().rev().collect();
            tail.contains("ee key too small") || tail.contains("AH02562")
        }
        Err(_) => false,
    }
}

/// Generate a fresh 2048-bit self-signed certificate with the tree's own
/// openssl. The previous files remain in the update backup.
fn regenerate_server_cert(basedir: &Path, log: &mut dyn FnMut(String, bool)) -> Result<(), String> {
    let ossl = basedir.join("apache\\bin\\openssl.exe");
    if !ossl.is_file() {
        return Err("openssl.exe not found: cannot regenerate the certificate".into());
    }
    // Apache Lounge builds of openssl.exe bake in C:\Apache24-64\conf\openssl.cnf,
    // which does not exist: hand it a minimal request config of our own and
    // generate in a scratch dir, only copying the artifacts over once real.
    let work = basedir.join("tmp\\update\\certgen");
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let cnf = work.join("mini.cnf");
    std::fs::write(&cnf, "[req]\ndistinguished_name = dn\n[dn]\n").map_err(|e| e.to_string())?;
    let key = work.join("server.key");
    let crt = work.join("server.crt");
    let _ = std::fs::remove_file(&key);
    let _ = std::fs::remove_file(&crt);
    let pid = run_process(
        &format!(
            "\"{}\" req -x509 -nodes -days 3650 -newkey rsa:2048 -config \"{}\" -keyout \"{}\" -out \"{}\" -subj \"/C=DE/O=XAMPP/CN=localhost\" -addext \"subjectAltName=DNS:localhost\"",
            ossl.to_string_lossy(),
            cnf.to_string_lossy(),
            key.to_string_lossy(),
            crt.to_string_lossy()
        ),
        basedir,
        SW_HIDE,
    )?;
    for _ in 0..120 {
        std::thread::sleep(std::time::Duration::from_millis(250));
        if procs::process_path(pid).is_empty() {
            break;
        }
    }
    let real = |p: &Path| p.metadata().map(|m| m.len() > 200).unwrap_or(false);
    if !real(&crt) || !real(&key) {
        return Err("openssl produced no certificate".into());
    }
    let dkey = basedir.join("apache\\conf\\ssl.key\\server.key");
    let dcrt = basedir.join("apache\\conf\\ssl.crt\\server.crt");
    if let Some(d) = dkey.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if let Some(d) = dcrt.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    std::fs::copy(&key, &dkey).map_err(|e| e.to_string())?;
    std::fs::copy(&crt, &dcrt).map_err(|e| e.to_string())?;
    log(
        "a fresh 2048-bit self-signed certificate is in place (the old one stays in the update backup)"
            .into(),
        false,
    );
    Ok(())
}

/// Stop the module, swap its tree, start it again. Blocking by design, so it
/// runs on a worker thread (or under --update-apply), never on the UI thread.
fn run_apply(
    basedir: &Path,
    info: &update::Info,
    keep: usize,
    limit: u64,
    ports: &[u16],
    mod_name: &str,
    binary: &str,
    log: &mut dyn FnMut(String, bool),
) -> Result<update::Applied, String> {
    let killed = stop_module_blocking(ports);
    let was_running = !killed.is_empty();
    if killed.is_empty() {
        log(
            format!("{mod_name} was not running; no port to release").into(),
            false,
        );
    } else {
        let list: Vec<String> = killed.iter().map(|p| p.to_string()).collect();
        log(
            format!("{mod_name} stopped (pid {})", list.join(", ")).into(),
            false,
        );
    }
    if info.comp == update::Comp::Mysql {
        let port = ports.first().copied().unwrap_or(3306);
        if let Err(e) = checkpoint_mysql_datadir(basedir, binary, port, log) {
            log("apply aborted before any change".into(), true);
            return Err(e);
        }
    }
    let ap = update::apply(basedir, info, keep, limit, log, &mut |_done, _total| {})?;
    log(
        format!("previous build kept in {}", ap.backup.display()).into(),
        false,
    );
    // The new tree may rename its daemon (mysqld.exe -> mariadbd.exe since 10.5):
    // the smoke test must run the exe apply() actually found, not the INI name.
    let smoke = if ap.exe.is_empty() {
        binary.to_string()
    } else {
        ap.exe.clone()
    };
    if info.comp != update::Comp::Php
        && info.comp != update::Comp::Phpmyadmin
        && smoke != binary
    {
        log(format!("daemon renamed: {binary} -> {smoke}").into(), false);
    }
    // PHP is mod_php inside Apache: it owns no daemon. Prove the new CLI runs
    // by letting it write a marker file, then put Apache back only when it had
    // been running. phpMyAdmin is even quieter: plain files, no smoke beyond
    // the RELEASE-DATE marker apply() already checked.
    let started = if info.comp == update::Comp::Php {
        smoke_php(basedir).and_then(|()| {
            if was_running {
                start_module_blocking(basedir, mod_name, binary)
            } else {
                Ok(())
            }
        })
    } else if info.comp == update::Comp::Phpmyadmin {
        if was_running {
            start_module_blocking(basedir, mod_name, binary)
        } else {
            Ok(())
        }
    } else {
        start_module_blocking(basedir, mod_name, &smoke)
    };
    match started {
        Ok(()) => {
            if info.comp == update::Comp::Mysql {
                run_system_upgrade(basedir, ports, log);
            }
            if was_running {
                log(
                    format!("{mod_name} is back up on the new build").into(),
                    false,
                );
            } else {
                let msg = match info.comp {
                    update::Comp::Php => "PHP smoke test ok on the new build".to_string(),
                    update::Comp::Phpmyadmin => {
                        "phpMyAdmin files in place on the new build".to_string()
                    }
                    _ => format!("{mod_name} smoke test ok on the new build"),
                };
                log(msg, false);
                if info.comp != update::Comp::Php && info.comp != update::Comp::Phpmyadmin {
                    stop_module_blocking(ports);
                    log(format!("{mod_name} left stopped, as before").into(), false);
                }
            }
            Ok(ap)
        }
        Err(e) => {
            log(e.clone().into(), true);
            // Apache Lounge ships newer OpenSSL than the current tree; OpenSSL
            // 3.5+ rejects XAMPP's ancient 1024-bit certificate outright. The
            // old files stay in the backup, so replace them and retry once.
            let mut started = false;
            if info.comp == update::Comp::Apache && apache_cert_rejected(basedir) {
                log(
                    "mod_ssl rejects the old self-signed certificate (key too small for the new OpenSSL); generating a 2048-bit one".into(),
                    true,
                );
                match regenerate_server_cert(basedir, log) {
                    Ok(()) => match start_module_blocking(basedir, mod_name, &smoke) {
                        Ok(()) => started = true,
                        Err(e2) => log(
                            format!("the new build still did not start: {e2}").into(),
                            true,
                        ),
                    },
                    Err(ce) => log(
                        format!("certificate regeneration failed: {ce}").into(),
                        true,
                    ),
                }
            }
            if started {
                if was_running {
                    log(
                        format!("{mod_name} is back up on the new build").into(),
                        false,
                    );
                } else {
                    log(
                        format!("{mod_name} smoke test ok on the new build").into(),
                        false,
                    );
                    stop_module_blocking(ports);
                    log(format!("{mod_name} left stopped, as before").into(), false);
                }
                return Ok(ap);
            }
            log("the new build did not start: rolling back".into(), true);
            update::rollback(basedir, info.comp, &ap.backup, log);
            match start_module_blocking(basedir, mod_name, binary) {
                Ok(()) => {
                    log(
                        format!("{mod_name} is back on the previous build").into(),
                        false,
                    );
                    if !was_running {
                        stop_module_blocking(ports);
                    }
                }
                Err(e2) => log(
                    format!(
                        "auto-restore did not bring {mod_name} up: {e2}\n\
                         manual restore: move {} back over {}",
                        ap.backup.join(info.comp.dir()).display(),
                        basedir.join(info.comp.dir()).display()
                    )
                    .into(),
                    true,
                ),
            }
            Err(e)
        }
    }
}

/// Worker side of a restore: stop the module, put the old tree back, smoke
/// start it, then leave it in the state it was in before.
fn run_restore(
    basedir: &Path,
    comp: update::Comp,
    backup: &Path,
    ports: &[u16],
    mod_name: &str,
    binary: &str,
    log: &mut dyn FnMut(String, bool),
) -> Result<String, String> {
    let killed = stop_module_blocking(ports);
    let was_running = !killed.is_empty();
    if !killed.is_empty() {
        let list: Vec<String> = killed.iter().map(|p| p.to_string()).collect();
        log(
            format!("{mod_name} stopped (pid {})", list.join(", ")).into(),
            false,
        );
    }
    update::rollback(basedir, comp, backup, log);
    // The restored tree may carry a different daemon name than the INI says
    // (mariadbd.exe -> mysqld.exe when going back before MariaDB 10.5).
    let dir = basedir.join(comp.dir());
    let rel = update::find_exe(&dir, comp).unwrap_or(comp.exe());
    let exe = rel.rsplit('/').next().unwrap_or(rel).to_string();
    if comp == update::Comp::Php {
        smoke_php(basedir)?;
        log("PHP smoke test ok on the restored build".into(), false);
        if was_running {
            start_module_blocking(basedir, mod_name, binary)?;
        }
        return Ok(exe);
    }
    if comp == update::Comp::Phpmyadmin {
        if was_running {
            start_module_blocking(basedir, mod_name, binary)?;
        }
        return Ok(exe);
    }
    start_module_blocking(basedir, mod_name, &exe)?;
    // Same rule as apply: the swap is proven by a smoke start, but a module
    // that was stopped must stay stopped.
    if !was_running {
        stop_module_blocking(ports);
        log(format!("{mod_name} left stopped, as before").into(), false);
    }
    Ok(exe)
}

/// Ask the feeds what is newer. Runs on a worker thread; the answer is rendered
/// by upd_drain(). The AllowMajor box in the update window wins over the INI and
/// is written back, so the checkbox survives a restart.
fn upd_check(app: &AppRc, _ui: &Ui) {
    let (tx, rx) = std::sync::mpsc::channel();
    let persist;
    let (basedir, allow, line) = {
        let mut a = app.borrow_mut();
        if a.upd_busy {
            return;
        }
        let win = a.upd_win.clone();
        let allow = match win.as_ref().map(|w| w.get_allow_major()) {
            Some(v) => v,
            None => a.cfg.upd_allow_major,
        };
        persist = allow != a.cfg.upd_allow_major;
        a.cfg.upd_allow_major = allow;
        a.upd_busy = true;
        a.upd_rx = Some(rx);
        (a.basedir.clone(), allow, a.cfg.upd_target_line.clone())
    };
    if persist {
        let a = app.borrow();
        let _ = config::save_ini(&a.ini_path, &a.cfg.to_ini());
    }
    if let Some(w) = app.borrow().upd_win.clone() {
        w.set_busy(true);
        w.set_status("Contacting the upstream feeds...".into());
    }
    add_log(
        &mut app.borrow_mut(),
        _ui,
        "update",
        "Checking the apache, mariadb, php and phpMyAdmin feeds...",
        LogType::Info,
    );
    std::thread::spawn(move || {
        let res = update::check_all(&basedir, allow, &line);
        let _ = tx.send(UpdMsg::Checked(res));
    });
}

/// Apply one row of the update window on a worker thread.
fn upd_apply(app: &AppRc, _ui: &Ui, row: usize) {
    let (info, ports, name, binary, keep, limit, basedir) = {
        let a = app.borrow();
        if a.upd_busy {
            return;
        }
        let info = match (a.upd_info.get(row), a.upd_sel.get(row)) {
            (Some(list), Some(sel)) => match list.get(*sel) {
                Some(i) => i.clone(),
                None => return,
            },
            _ => return,
        };
        let mi = info.comp.modules()[0];
        let is_my = info.comp == update::Comp::Mysql;
        (
            info,
            a.modules[mi].check_ports.clone(),
            a.modules[mi].name,
            if is_my {
                a.cfg.mysql_binary.clone()
            } else {
                a.cfg.apache_binary.clone()
            },
            a.cfg.upd_keep_backups.max(0) as usize,
            a.cfg.upd_data_backup_limit_mb.max(1) as u64,
            a.basedir.clone(),
        )
    };
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let mut a = app.borrow_mut();
        a.upd_busy = true;
        a.upd_rx = Some(rx);
    }
    if let Some(w) = app.borrow().upd_win.clone() {
        w.set_busy(true);
        w.set_status(format!("Applying {} {}...", name, info.available).into());
    }
    std::thread::spawn(move || {
        let mut lg = |line: String, warn: bool| {
            let _ = tx.send(UpdMsg::Log(line, warn));
        };
        let r = run_apply(&basedir, &info, keep, limit, &ports, name, &binary, &mut lg);
        let _ = tx.send(UpdMsg::Finished(r));
    });
}

/// Build one update-window row for `comp` from its candidate list. `sel` marks
/// which candidate the target dropdown shows; labels come from the feed's own
/// line/status metadata (LTS, Rolling, RC test, EOL).
fn upd_row(
    comp: update::Comp,
    installed: String,
    list: &[update::Info],
    sel: usize,
    restorable: bool,
) -> UpdateInfo {
    let cur = list.get(sel);
    UpdateInfo {
        name: comp.label().into(),
        from_ver: installed.into(),
        targets: ModelRc::from(Rc::new(VecModel::from(
            list.iter()
                .map(|i| SharedString::from(update::target_label(i)))
                .collect::<Vec<SharedString>>(),
        ))),
        sel: sel as i32,
        size: match cur {
            Some(i) if i.size > 0 => format!("{} MB", (i.size + 1_048_575) / 1_048_576).into(),
            _ => "?".into(),
        },
        note: cur.map(|i| i.note.clone()).unwrap_or_default().into(),
        updatable: !list.is_empty(),
        restorable,
        error: SharedString::default(),
    }
}

/// A different target was picked in a row's dropdown: remember the index and
/// refresh the row, so size and status columns follow the selection.
fn upd_select(app: &AppRc, row: usize, sel: i32) {
    if sel < 0 {
        return;
    }
    let sel = sel as usize;
    let mut a = app.borrow_mut();
    let comp = match a.upd_comps.get(row) {
        Some(c) => *c,
        None => return,
    };
    let list = match a.upd_info.get(row) {
        Some(l) => l,
        None => return,
    };
    if sel >= list.len() {
        return;
    }
    let restorable = update::find_backup(&a.basedir, comp).is_some();
    let installed = list
        .first()
        .map(|i| i.installed.clone())
        .unwrap_or_else(|| "?".into());
    let data = upd_row(comp, installed, list, sel, restorable);
    a.upd_sel[row] = sel;
    slint::Model::set_row_data(&*a.upd_model, row, data);
}

/// Restore one row of the update window from its backup, on a worker thread.
fn upd_restore(app: &AppRc, _ui: &Ui, row: usize) {
    let (comp, backup, basedir, ports, name, binary) = {
        let a = app.borrow();
        if a.upd_busy {
            return;
        }
        let comp = match a.upd_comps.get(row) {
            Some(c) => *c,
            None => return,
        };
        let backup = match update::find_backup(&a.basedir, comp) {
            Some(p) => p,
            None => return,
        };
        let mi = comp.modules()[0];
        (
            comp,
            backup,
            a.basedir.clone(),
            a.modules[mi].check_ports.clone(),
            a.modules[mi].name,
            if comp == update::Comp::Mysql {
                a.cfg.mysql_binary.clone()
            } else {
                a.cfg.apache_binary.clone()
            },
        )
    };
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let mut a = app.borrow_mut();
        a.upd_busy = true;
        a.upd_rx = Some(rx);
    }
    if let Some(w) = app.borrow().upd_win.clone() {
        w.set_busy(true);
        w.set_status(format!("Restoring {}...", comp.label()).into());
    }
    std::thread::spawn(move || {
        let mut lg = |line: String, warn: bool| {
            let _ = tx.send(UpdMsg::Log(line, warn));
        };
        let r = run_restore(&basedir, comp, &backup, &ports, name, &binary, &mut lg);
        let _ = tx.send(UpdMsg::Restored(comp, r));
    });
}

/// A MariaDB major jump renames the server binary (mysqld.exe -> mariadbd.exe).
/// Keep the INI in step, otherwise the next start would look for a file that no
/// longer exists.
fn sync_binary_name(app: &mut App, comp: update::Comp, exe: &str, ui: &Ui) {
    if exe.is_empty() {
        return;
    }
    let my = comp == update::Comp::Mysql;
    if !matches!(comp, update::Comp::Apache | update::Comp::Mysql) {
        return;
    }
    let cur = if my {
        &app.cfg.mysql_binary
    } else {
        &app.cfg.apache_binary
    };
    if cur == exe {
        return;
    }
    let old = cur.clone();
    if my {
        app.cfg.mysql_binary = exe.to_string();
    } else {
        app.cfg.apache_binary = exe.to_string();
    }
    let _ = config::save_ini(&app.ini_path, &app.cfg.to_ini());
    add_log(
        app,
        ui,
        "update",
        &format!("BinaryNames in xampp-rs.ini: {old} -> {exe}"),
        LogType::Info,
    );
}

/// Render whatever the worker sent. Called from the timer so all Slint writes
/// happen on the UI thread.
fn upd_drain(app: &mut App, ui: &Ui) {
    let rx = match app.upd_rx.take() {
        Some(r) => r,
        None => return,
    };
    let mut pending = true;
    while let Ok(m) = rx.try_recv() {
        match m {
            UpdMsg::Log(l, warn) => add_log(
                app,
                ui,
                "update",
                &l,
                if warn { LogType::Error } else { LogType::Info },
            ),
            UpdMsg::Checked(res) => {
                pending = false;
                app.upd_busy = false;
                app.upd_info.clear();
                app.upd_sel.clear();
                app.upd_model.clear();
                app.upd_comps.clear();
                let (mut found, mut errs) = (0usize, 0usize);
                for (comp, r) in res {
                    let restorable = update::find_backup(&app.basedir, comp).is_some();
                    match r {
                        Ok(list) => {
                            if !list.is_empty() {
                                found += 1;
                            }
                            let installed = match list.first() {
                                Some(i) => i.installed.clone(),
                                None => update::installed_version(&app.basedir, comp)
                                    .map(|v| v.show())
                                    .unwrap_or_else(|_| "?".into()),
                            };
                            app.upd_model
                                .push(upd_row(comp, installed, &list, 0, restorable));
                            app.upd_sel.push(0);
                            app.upd_info.push(list);
                        }
                        Err(e) => {
                            errs += 1;
                            app.upd_model.push(UpdateInfo {
                                name: comp.label().into(),
                                restorable,
                                error: e.into(),
                                ..Default::default()
                            });
                            app.upd_sel.push(0);
                            app.upd_info.push(Vec::new());
                        }
                    }
                    app.upd_comps.push(comp);
                }
                let badge = match (found, errs) {
                    (0, 0) => "all up to date".to_string(),
                    (n, 0) => format!("{n} update(s) ready"),
                    (0, n) => format!("{n} feed(s) unreachable"),
                    (n, e) => format!("{n} update(s), {e} feed error(s)"),
                };
                ui.main.set_update_badge(badge.clone().into());
                if let Some(w) = app.upd_win.clone() {
                    w.set_busy(false);
                    w.set_status(badge.into());
                }
            }
            UpdMsg::Finished(r) => {
                pending = false;
                app.upd_busy = false;
                match r {
                    Ok(ap) => {
                        add_log(
                            app,
                            ui,
                            "update",
                            "Update finished, component restarted on the new build.",
                            LogType::Info,
                        );
                        sync_binary_name(app, ap.comp, &ap.exe, ui);
                    }
                    Err(e) => add_log(
                        app,
                        ui,
                        "update",
                        &format!("Update failed: {e}"),
                        LogType::Error,
                    ),
                }
                if let Some(w) = app.upd_win.clone() {
                    w.set_status(if app.upd_busy {
                        "".into()
                    } else {
                        "Done.".into()
                    });
                }
            }
            UpdMsg::Restored(comp, r) => {
                pending = false;
                app.upd_busy = false;
                match r {
                    Ok(exe) => {
                        add_log(
                            app,
                            ui,
                            "update",
                            &format!("{} restored to the previous build.", comp.label()),
                            LogType::Info,
                        );
                        sync_binary_name(app, comp, &exe, ui);
                    }
                    Err(e) => add_log(
                        app,
                        ui,
                        "update",
                        &format!("Restore failed: {e}"),
                        LogType::Error,
                    ),
                }
                if let Some(w) = app.upd_win.clone() {
                    w.set_status("Done.".into());
                }
            }
        }
    }
    ui.main.set_update_busy(app.upd_busy);
    if let Some(w) = app.upd_win.clone() {
        w.set_busy(app.upd_busy);
    }
    if pending {
        app.upd_rx = Some(rx);
    }
}

/// About dialog: the panel's own version and the XAMPP tree it runs on.
fn show_about_window(app: &AppRc, _ui: &Ui) {
    let existing = app.borrow().about_win.clone();
    let win = match existing {
        Some(w) => w,
        None => {
            let Ok(w) = AboutWindow::new() else { return };
            let w = Rc::new(w);
            let wc = w.clone();
            w.on_close_it(move || {
                let _ = wc.hide();
            });
            w.window()
                .on_close_requested(|| CloseRequestResponse::HideWindow);
            app.borrow_mut().about_win = Some(w.clone());
            w
        }
    };
    win.set_app_version(format!("Version xampp-rs v{}", env!("CARGO_PKG_VERSION")).into());
    win.show().ok();
}

/// Open or re-show the update window. The first open starts a check right away
/// so the user never has to press twice.
fn show_updates(app: &AppRc, ui: &Ui) {
    let (win, fresh) = {
        let mut a = app.borrow_mut();
        if let Some(w) = a.upd_win.clone() {
            (w, false)
        } else {
            let Ok(w) = UpdateWindow::new() else {
                return;
            };
            let w = Rc::new(w);
            w.set_rows(ModelRc::from(a.upd_model.clone()));
            w.set_allow_major(a.cfg.upd_allow_major);
            w.window()
                .on_close_requested(|| CloseRequestResponse::HideWindow);
            a.upd_win = Some(w.clone());
            (w, true)
        }
    };
    win.set_allow_major(app.borrow().cfg.upd_allow_major);
    let busy = app.borrow().upd_busy;
    win.set_busy(busy);
    let _ = win.show();
    if fresh {
        let app_w = app.clone();
        let ui_w = ui.clone();
        win.on_check_now(move || upd_check(&app_w, &ui_w));
        let app_w = app.clone();
        let ui_w = ui.clone();
        win.on_do_apply(move |row| upd_apply(&app_w, &ui_w, row as usize));
        let app_w = app.clone();
        let ui_w = ui.clone();
        win.on_do_restore(move |row| upd_restore(&app_w, &ui_w, row as usize));
        let app_w = app.clone();
        win.on_set_target(move |row, sel| upd_select(&app_w, row as usize, sel));
        let app_w = app.clone();
        win.on_close_win(move || {
            if let Some(w) = app_w.borrow().upd_win.clone() {
                let _ = w.hide();
            }
        });
    }
    if !busy {
        upd_check(app, ui);
    }
}

fn terminate_pid(pid: u32) -> bool {
    unsafe {
        match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(h) => {
                let ok = TerminateProcess(h, 1).is_ok();
                let _ = CloseHandle(h);
                ok
            }
            Err(_) => false,
        }
    }
}

fn shell_open(target: &str, operation: &str) -> bool {
    unsafe {
        let op = wide(operation);
        let file = wide(target);
        let ret = ShellExecuteW(
            None,
            PCWSTR(op.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOW,
        );
        ret.0 as isize > 32
    }
}

/// ---------------------------------------------------------------- logging

fn add_log(app: &mut App, ui: &Ui, module: &str, text: &str, lt: LogType) {
    if lt == LogType::Debug && !app.cfg.show_debug {
        return;
    }
    let ts = local_time();
    app.log_file.push(format!("{ts}  [{module}]\t{text}"));
    let color = match lt {
        LogType::Default => (213, 217, 224),
        LogType::Info => (106, 163, 255),
        LogType::Error => (255, 92, 92),
        LogType::Debug => (111, 116, 125),
    };
    ui.log_model.push(LogLine {
        time: ts.into(),
        module: module.into(),
        text: text.into(),
        color: brush(color),
    });
    if ui.log_model.row_count() > MAX_LOG_LINES {
        ui.log_model.remove(0);
    }
    // Le défilement vers le bas est fait au prochain tick (le layout doit
    // avoir été recalculé pour que content-height soit à jour).
    app.log_dirty = true;
}

fn log_unexpected_shutdown(app: &mut App, ui: &Ui, name: &str) {
    let lines = [
        format!("Error: {name} shutdown unexpectedly."),
        "This may be due to a blocked port, missing dependencies, ".into(),
        "improper privileges, a crash, or a shutdown by another method.".into(),
        "Press the Logs button to view error logs and check".into(),
        "the Windows Event Viewer for more clues".into(),
        "If you need more help, copy and post this".into(),
        "entire log window on the forums".into(),
    ];
    for l in lines {
        add_log(app, ui, name, &l, LogType::Error);
    }
}

fn write_log_file(app: &App) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&app.log_path)
    {
        for line in &app.log_file {
            let _ = writeln!(f, "{line}");
        }
        let _ = writeln!(f);
    }
}

// ---------------------------------------------------------------- module logic

fn module_ports(app: &App, m: &Module) -> String {
    let mut ports: Vec<u16> = Vec::new();
    for pid in &m.pids {
        ports.extend(netstat::ports_for_pid(&app.tcp, *pid));
    }
    ports.sort_unstable();
    ports.dedup();
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Port of tApache/tMySQL.CheckPorts (services branch dropped).
fn check_ports(app: &mut App, ui: &Ui, idx: usize) {
    if !app.cfg.check_ports {
        return;
    }
    let name = app.modules[idx].name;
    let ports = app.modules[idx].check_ports.clone();
    let rel = if name == "Apache" {
        format!("apache\\bin\\{}", app.cfg.apache_binary)
    } else {
        format!("mysql\\bin\\{}", app.cfg.mysql_binary)
    };
    let server_app = app.basedir.join(rel).to_string_lossy().to_lowercase();
    add_log(app, ui, name, "Checking default ports...", LogType::Debug);
    for port in ports {
        let blocker_pid = match netstat::pid_on_port(&app.tcp, port) {
            Some(p) if p != 0 => p,
            _ => continue,
        };
        let blocker_name = app
            .names
            .get(&blocker_pid)
            .cloned()
            .unwrap_or_else(|| format!("PID {blocker_pid}"));
        add_log(
            app,
            ui,
            name,
            &format!("Portblocker Detected: {blocker_name}"),
            LogType::Debug,
        );
        let pbpath = procs::process_path(blocker_pid);
        add_log(
            app,
            ui,
            name,
            &format!("Portblocker Path: {pbpath}"),
            LogType::Debug,
        );
        if pbpath.to_lowercase() == server_app {
            add_log(
                app,
                ui,
                name,
                &format!("XAMPP {name} is already running on port {port}"),
                LogType::Info,
            );
        } else {
            app.modules[idx].error = true;
            add_log(app, ui, name, "Problem detected!", LogType::Error);
            add_log(
                app,
                ui,
                name,
                &format!("Port {port} in use by \"{pbpath}\" with PID {blocker_pid}!"),
                LogType::Error,
            );
            add_log(
                app,
                ui,
                name,
                &format!("{name} WILL NOT start without the configured ports free!"),
                LogType::Error,
            );
            add_log(
                app,
                ui,
                name,
                "You need to uninstall/disable/reconfigure the blocking application",
                LogType::Error,
            );
            add_log(
                app,
                ui,
                name,
                &format!(
                    "or reconfigure {name} and the Control Panel to listen on a different port"
                ),
                LogType::Error,
            );
        }
    }
}

fn start_module(app: &mut App, ui: &Ui, idx: usize) {
    app.modules[idx].phase = Phase::Starting;
    app.tcp = netstat::tcp_table();
    check_ports(app, ui, idx);
    let name = app.modules[idx].name;
    add_log(
        app,
        ui,
        name,
        &format!("Attempting to start {name} app..."),
        LogType::Default,
    );
    let cmdline = if name == "Apache" {
        format!(
            "\"{}\"",
            app.basedir
                .join(format!("apache\\bin\\{}", app.cfg.apache_binary))
                .to_string_lossy()
        )
    } else {
        let exe = app
            .basedir
            .join(format!("mysql\\bin\\{}", app.cfg.mysql_binary));
        let ini = app.basedir.join("mysql\\bin\\my.ini");
        format!(
            "\"{}\" --defaults-file=\"{}\" --standalone",
            exe.to_string_lossy(),
            ini.to_string_lossy()
        )
    };
    add_log(
        app,
        ui,
        name,
        &format!("Executing \"{cmdline}\""),
        LogType::Debug,
    );
    let spawn = || run_process(&cmdline, &app.basedir, SW_HIDE);
    let res = if name == "Apache" { with_php_env(&app.basedir, spawn) } else { spawn() };
    match res {
        Ok(pid) => add_log(
            app,
            ui,
            name,
            &format!("Return code: 0 (PID {pid})"),
            LogType::Debug,
        ),
        Err(msg) => add_log(
            app,
            ui,
            name,
            &format!("There may be an error, return code: {msg}"),
            LogType::Error,
        ),
    }
}

fn stop_module(app: &mut App, ui: &Ui, idx: usize) {
    app.modules[idx].phase = Phase::Stopping;
    let name = app.modules[idx].name;
    let pids = app.modules[idx].pids.clone();
    if pids.is_empty() {
        add_log(app, ui, name, "No PIDs found?!", LogType::Default);
        return;
    }
    for pid in pids {
        if name == "Apache" {
            add_log(
                app,
                ui,
                name,
                &format!("Attempting to stop {name} (PID: {pid})"),
                LogType::Default,
            );
        } else {
            add_log(
                app,
                ui,
                name,
                &format!("Attempting to stop {name} app... (PID: {pid})"),
                LogType::Default,
            );
        }
        if !terminate_pid(pid) {
            add_log(
                app,
                ui,
                name,
                &format!("Problem killing PID {pid}"),
                LogType::Error,
            );
            add_log(
                app,
                ui,
                name,
                "Check that you have the proper privileges",
                LogType::Error,
            );
        }
    }
}

/// Port of tApache/tMySQL.UpdateStatus (services branch dropped).
fn update_module(app: &mut App, ui: &Ui, idx: usize) {
    let basedir_l = app
        .basedir
        .to_string_lossy()
        .replace('\\', "/")
        .to_lowercase();
    let binary = app.modules[idx].binary.clone();
    let mut sorted: Vec<(u32, String)> = app
        .names
        .iter()
        .map(|(pid, name)| (*pid, name.to_lowercase()))
        .collect();
    sorted.sort();
    let mut pids: Vec<u32> = Vec::new();
    for (pid, pname) in sorted {
        if !pname.starts_with(&binary) {
            continue;
        }
        let path = procs::process_path(pid).replace('\\', "/").to_lowercase();
        if !path.is_empty() && path.contains(&basedir_l) {
            pids.push(pid);
        }
    }
    {
        let m = &mut app.modules[idx];
        m.pids = pids;
        m.running = !m.pids.is_empty();
        if m.running {
            m.error = false;
        }
    }

    let name = app.modules[idx].name;
    let running = app.modules[idx].running;
    let first = app.modules[idx].old_running.is_none();
    let prev = app.modules[idx].old_running;
    let running_changed = prev.map_or(true, |o| o != running);
    let count_changed = app.modules[idx].old_pid_count != app.modules[idx].pids.len();
    let was_starting = app.modules[idx].phase == Phase::Starting;

    if running_changed || count_changed {
        if !first && running_changed {
            if running {
                add_log(
                    app,
                    ui,
                    name,
                    "Status change detected: running",
                    LogType::Default,
                );
            } else {
                add_log(
                    app,
                    ui,
                    name,
                    "Status change detected: stopped",
                    LogType::Default,
                );
                if was_starting {
                    log_unexpected_shutdown(app, ui, name);
                }
            }
        }
        app.modules[idx].old_running = Some(running);
    }
    app.modules[idx].old_pid_count = app.modules[idx].pids.len();
}

fn refresh_and_update(app: &mut App, ui: &Ui) {
    app.tcp = netstat::tcp_table();
    app.names = procs::process_name_map();
    for i in 0..app.modules.len() {
        update_module(app, ui, i);
    }
    sync_modules(app, ui);
}

fn sync_modules(app: &App, ui: &Ui) {
    for (i, m) in app.modules.iter().enumerate() {
        let (bg, fg, label) = if m.error && !m.running {
            (BG_ERROR, FG_ERROR, "ERROR")
        } else if m.running && m.pids.len() >= m.expect_pids {
            (BG_RUNNING, FG_RUNNING, "RUNNING")
        } else if m.running {
            (BG_PARTIAL, FG_PARTIAL, "PARTIAL")
        } else {
            (BG_STOPPED, FG_STOPPED, "STOPPED")
        };
        ui.mod_model.set_row_data(
            i,
            ModuleInfo {
                name: m.name.into(),
                pid_text: m
                    .pids
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
                    .into(),
                port_text: module_ports(app, m).into(),
                status_brush: brush(bg),
                status_text: label.into(),
                status_fg: brush(fg),
                action_text: if m.running { "Stop" } else { "Start" }.into(),
                admin_enabled: m.running,
                start_enabled: true,
            },
        );
    }
}

// ---------------------------------------------------------------- actions

fn admin_module(app: &mut App, ui: &Ui, idx: usize) {
    let name = app.modules[idx].name;
    let url = if name == "Apache" {
        if app.cfg.apache_port == 80 {
            "http://localhost/".to_string()
        } else {
            format!("http://localhost:{}/", app.cfg.apache_port)
        }
    } else if app.cfg.apache_port == 80 {
        "http://localhost/phpmyadmin/".to_string()
    } else {
        format!("http://localhost:{}/phpmyadmin", app.cfg.apache_port)
    };
    if app.cfg.browser.is_empty() {
        add_log(
            app,
            ui,
            name,
            &format!("Executing \"{url}\""),
            LogType::Debug,
        );
        shell_open(&url, "open");
    } else {
        let cmdline = format!("{} {}", app.cfg.browser, url);
        add_log(
            app,
            ui,
            name,
            &format!("Executing \"{cmdline}\""),
            LogType::Debug,
        );
        let _ = run_process(&cmdline, &app.basedir, SW_SHOW);
    }
}

fn file_rows(app: &App, kind: &str, idx: usize) -> Vec<(String, String, bool)> {
    let rel: Vec<(&str, &str, bool)> = match (kind, app.modules[idx].name) {
        ("config", "Apache") => vec![
            ("Apache (httpd.conf)", "apache\\conf\\httpd.conf", false),
            (
                "Apache (httpd-ssl.conf)",
                "apache\\conf\\extra\\httpd-ssl.conf",
                false,
            ),
            (
                "Apache (httpd-xampp.conf)",
                "apache\\conf\\extra\\httpd-xampp.conf",
                false,
            ),
            ("PHP (php.ini)", "php\\php.ini", false),
            (
                "phpMyAdmin (config.inc.php)",
                "phpMyAdmin\\config.inc.php",
                false,
            ),
            ("<Browse> [Apache]", "apache", true),
            ("<Browse> [PHP]", "php", true),
            ("<Browse> [phpMyAdmin]", "phpMyAdmin", true),
        ],
        ("config", _) => vec![
            ("my.ini", "mysql\\bin\\my.ini", false),
            ("<Browse>", "mysql", true),
        ],
        ("logs", "Apache") => vec![
            ("Apache (access.log)", "apache\\logs\\access.log", false),
            ("Apache (error.log)", "apache\\logs\\error.log", false),
            ("PHP (php_error_log)", "php\\logs\\php_error_log", false),
            ("<Browse> [Apache]", "apache\\logs", true),
            ("<Browse> [PHP]", "php\\logs", true),
        ],
        ("logs", _) => vec![
            ("mysql_error.log", "mysql\\data\\mysql_error.log", false),
            ("<Browse>", "mysql\\data", true),
        ],
        _ => return Vec::new(),
    };
    rel.into_iter()
        .map(|(label, path, is_dir)| {
            let full = app.basedir.join(path).to_string_lossy().to_string();
            (label.to_string(), full, is_dir)
        })
        .collect()
}

fn open_file_row(app: &mut App, ui: &Ui, path: &str, is_dir: bool) {
    if is_dir {
        add_log(
            app,
            ui,
            "main",
            &format!("Executing \"{path}\""),
            LogType::Debug,
        );
        shell_open(path, "explore");
        return;
    }
    if !Path::new(path).exists() {
        add_log(
            app,
            ui,
            "main",
            &format!("File not found: {path}"),
            LogType::Error,
        );
        return;
    }
    let editor = app.cfg.editor.trim().to_string();
    if editor.is_empty() || editor.eq_ignore_ascii_case("notepad.exe") {
        add_log(
            app,
            ui,
            "main",
            &format!("Executing \"{path}\""),
            LogType::Debug,
        );
        shell_open(path, "open");
    } else {
        let cmdline = format!("\"{}\" \"{}\"", editor, path);
        add_log(
            app,
            ui,
            "main",
            &format!("Executing \"{cmdline}\""),
            LogType::Debug,
        );
        if run_process(&cmdline, &app.basedir, SW_SHOW).is_err() {
            add_log(
                app,
                ui,
                "main",
                &format!("Could not launch editor \"{editor}\", using default association"),
                LogType::Error,
            );
            shell_open(path, "open");
        }
    }
}

fn show_file_window(app: &AppRc, ui: &Ui, kind: &str, idx: usize) {
    let (heading, rows) = {
        let a = app.borrow();
        let name = a.modules[idx].name;
        let heading = if kind == "config" {
            format!("{name} configuration files")
        } else {
            format!("{name} log files")
        };
        let rows = file_rows(&a, kind, idx)
            .into_iter()
            .map(|(label, path, is_dir)| FileRow {
                exists: is_dir || Path::new(&path).exists(),
                is_dir,
                label: label.into(),
                path: path.into(),
            })
            .collect::<Vec<FileRow>>();
        (heading, rows)
    };
    {
        let a = app.borrow();
        a.file_model.clear();
        for r in rows {
            a.file_model.push(r);
        }
    }
    let existing = app.borrow().file_win.clone();
    let win = match existing {
        Some(w) => w,
        None => {
            let Ok(w) = FileWindow::new() else { return };
            let w = Rc::new(w);
            w.set_rows(ModelRc::from(app.borrow().file_model.clone()));
            let app_cb = app.clone();
            let ui_cb = ui.clone();
            w.on_open_row(move |i| {
                let row = app_cb.borrow().file_model.row_data(i as usize);
                if let Some(r) = row {
                    let mut a = app_cb.borrow_mut();
                    open_file_row(&mut a, &ui_cb, &r.path.to_string(), r.is_dir);
                }
            });
            let app_cb = app.clone();
            w.on_close_win(move || {
                let a = app_cb.borrow();
                if let Some(w) = &a.file_win {
                    let _ = w.hide();
                }
            });
            w.window()
                .on_close_requested(|| CloseRequestResponse::HideWindow);
            app.borrow_mut().file_win = Some(w.clone());
            w
        }
    };
    win.set_heading(heading.into());
    let _ = win.show();
}

fn show_settings_window(app: &AppRc, ui: &Ui) {
    let existing = app.borrow().settings_win.clone();
    let win = match existing {
        Some(w) => w,
        None => {
            let Ok(w) = ConfigWindow::new() else { return };
            let w = Rc::new(w);
            let app_cb = app.clone();
            let ui_cb = ui.clone();
            let wc = w.clone();
            w.on_save(move || {
                let mut a = app_cb.borrow_mut();
                let parse = |s: SharedString, old: u16| -> u16 { s.trim().parse().unwrap_or(old) };
                a.cfg.apache_port = parse(wc.get_apache_port(), a.cfg.apache_port);
                a.cfg.apache_ssl_port = parse(wc.get_apache_ssl_port(), a.cfg.apache_ssl_port);
                a.cfg.mysql_port = parse(wc.get_mysql_port(), a.cfg.mysql_port);
                a.cfg.check_ports = wc.get_check_ports();
                a.cfg.show_debug = wc.get_show_debug();
                a.cfg.editor = wc.get_editor().to_string();
                a.cfg.browser = wc.get_browser().to_string();
                a.modules[0].check_ports = vec![a.cfg.apache_port, a.cfg.apache_ssl_port];
                a.modules[1].check_ports = vec![a.cfg.mysql_port];
                a.cfg.save(&a.ini_path);
                add_log(&mut a, &ui_cb, "main", "Settings saved", LogType::Info);
                let _ = wc.hide();
            });
            let wc2 = w.clone();
            w.on_cancel(move || {
                let _ = wc2.hide();
            });
            w.window()
                .on_close_requested(|| CloseRequestResponse::HideWindow);
            app.borrow_mut().settings_win = Some(w.clone());
            w
        }
    };
    {
        let a = app.borrow();
        let cfg = &a.cfg;
        win.set_apache_port(cfg.apache_port.to_string().into());
        win.set_apache_ssl_port(cfg.apache_ssl_port.to_string().into());
        win.set_mysql_port(cfg.mysql_port.to_string().into());
        win.set_check_ports(cfg.check_ports);
        win.set_show_debug(cfg.show_debug);
        win.set_editor(cfg.editor.clone().into());
        win.set_browser(cfg.browser.clone().into());
    }
    let _ = win.show();
}

fn do_quit(app: &mut App, ui: &Ui) {
    if app.closing {
        return;
    }
    app.closing = true;
    add_log(app, ui, "main", "Deinitializing Modules", LogType::Default);
    for i in 0..app.modules.len() {
        if app.modules[i].running {
            stop_module(app, ui, i);
        }
    }
    add_log(
        app,
        ui,
        "main",
        "Deinitializing Control Panel",
        LogType::Default,
    );
    let pos = ui.main.window().position();
    let size = ui.main.window().size();
    app.cfg.win_left = pos.x;
    app.cfg.win_top = pos.y;
    app.cfg.win_width = size.width as i32;
    app.cfg.win_height = size.height as i32;
    app.cfg.save(&app.ini_path);
    write_log_file(app);
    let _ = slint::quit_event_loop();
}

// ---------------------------------------------------------------- entry point

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basedir = detect_basedir();
    let stem = exe_stem();
    let ini_path = basedir.join(format!("{stem}.ini"));
    let log_path = basedir.join(format!("{stem}.log"));
    let cfg = config::Config::load(&ini_path);

    let modules = vec![
        Module {
            name: "Apache",
            binary: cfg.apache_binary.to_lowercase(),
            check_ports: vec![cfg.apache_port, cfg.apache_ssl_port],
            expect_pids: 2,
            pids: Vec::new(),
            running: false,
            error: false,
            old_running: None,
            old_pid_count: 0,
            phase: Phase::Idle,
        },
        Module {
            name: "MySQL",
            binary: cfg.mysql_binary.to_lowercase(),
            check_ports: vec![cfg.mysql_port],
            expect_pids: 1,
            pids: Vec::new(),
            running: false,
            error: false,
            old_running: None,
            old_pid_count: 0,
            phase: Phase::Idle,
        },
    ];

    let app: AppRc = Rc::new(RefCell::new(App {
        basedir: basedir.clone(),
        ini_path,
        log_path,
        cfg: cfg.clone(),
        modules,
        tcp: Vec::new(),
        names: HashMap::new(),
        log_file: Vec::new(),
        log_dirty: false,
        file_win: None,
        file_model: Rc::new(VecModel::default()),
        settings_win: None,
        upd_win: None,
        about_win: None,
        upd_model: Rc::new(VecModel::default()),
        upd_info: Vec::new(),
        upd_sel: Vec::new(),
        upd_comps: Vec::new(),
        upd_rx: None,
        upd_busy: false,
        closing: false,
    }));

    let main_window = Rc::new(MainWindow::new()?);
    let mod_model = Rc::new(VecModel::from(
        app.borrow()
            .modules
            .iter()
            .map(|m| ModuleInfo {
                name: m.name.into(),
                pid_text: SharedString::default(),
                port_text: SharedString::default(),
                status_brush: brush(BG_STOPPED),
                status_text: "STOPPED".into(),
                status_fg: brush(FG_STOPPED),
                action_text: "Start".into(),
                admin_enabled: false,
                start_enabled: true,
            })
            .collect::<Vec<ModuleInfo>>(),
    ));
    let log_model = Rc::new(VecModel::<LogLine>::default());
    main_window.set_modules(ModelRc::from(mod_model.clone()));
    main_window.set_logs(ModelRc::from(log_model.clone()));
    main_window.set_basedir(basedir.to_string_lossy().to_string().into());

    let ui = Ui {
        main: main_window.clone(),
        log_model,
        mod_model,
    };

    if cfg.win_width > 0 && cfg.win_height > 0 {
        main_window.window().set_size(slint::LogicalSize::new(
            cfg.win_width as f32,
            cfg.win_height as f32,
        ));
    }
    if cfg.win_left >= 0 && cfg.win_top >= 0 {
        main_window
            .window()
            .set_position(slint::LogicalPosition::new(
                cfg.win_left as f32,
                cfg.win_top as f32,
            ));
    }

    // Startup log, mirrors TfMain.FormCreate.
    {
        let mut a = app.borrow_mut();
        add_log(
            &mut a,
            &ui,
            "main",
            "Initializing Control Panel",
            LogType::Default,
        );
        add_log(
            &mut a,
            &ui,
            "main",
            &format!("Windows Version: {}", windows_version()),
            LogType::Default,
        );
        add_log(
            &mut a,
            &ui,
            "main",
            &format!("XAMPP Version: {}", guess_xampp_version(&basedir)),
            LogType::Default,
        );
        add_log(
            &mut a,
            &ui,
            "main",
            &format!(
                "Control Panel Version: xampp-rs v{}",
                env!("CARGO_PKG_VERSION")
            ),
            LogType::Default,
        );
        if unsafe { IsUserAnAdmin().as_bool() } {
            add_log(
                &mut a,
                &ui,
                "main",
                "Running with Administrator rights - good!",
                LogType::Default,
            );
        } else {
            add_log(
                &mut a,
                &ui,
                "main",
                "You are not running with administrator rights!",
                LogType::Info,
            );
            add_log(
                &mut a,
                &ui,
                "main",
                "Some operations may fail or require elevation.",
                LogType::Info,
            );
        }
        let bd = basedir.to_string_lossy().to_string();
        add_log(
            &mut a,
            &ui,
            "main",
            &format!("XAMPP Installation Directory: \"{bd}\""),
            LogType::Default,
        );
        // Self-heal the runtime configuration on every launch: the tree may
        // have been copied from another machine, so php.ini path directives
        // are re-rooted onto this basedir (and the apache\bin fallback mirror
        // refreshed) before any module can start.
        update::patch_compat(&basedir, &mut |l, warn| {
            add_log(
                &mut a,
                &ui,
                "main",
                &l,
                if warn { LogType::Error } else { LogType::Info },
            )
        });
        if bd.contains(' ') {
            add_log(
                &mut a,
                &ui,
                "main",
                "WARNING: Your install directory contains spaces.  This may break programs/scripts",
                LogType::Info,
            );
        }
        if bd.chars().any(|c| "()[!@#$%^&*<>,?[]{}=+`~|".contains(c)) {
            add_log(&mut a, &ui, "main", "WARNING: Your install directory contains special characters.  This may break programs/scripts", LogType::Info);
        }
        add_log(
            &mut a,
            &ui,
            "main",
            "Checking for components",
            LogType::Default,
        );
        let mut missing = 0;
        for (sub, comp) in [
            ("apache\\bin", update::Comp::Apache),
            ("mysql\\bin", update::Comp::Mysql),
        ] {
            let want = if comp == update::Comp::Mysql {
                a.cfg.mysql_binary.clone()
            } else {
                a.cfg.apache_binary.clone()
            };
            let p = a.basedir.join(sub).join(&want);
            if p.exists() {
                add_log(
                    &mut a,
                    &ui,
                    "main",
                    &format!("Found {}", p.to_string_lossy()),
                    LogType::Debug,
                );
                continue;
            }
            // An update can rename the daemon (mysqld.exe -> mariadbd.exe) and
            // the INI may lag; find the real binary and keep the INI in step.
            match update::find_exe(&a.basedir.join(comp.dir()), comp) {
                Some(rel) => {
                    let found = a.basedir.join(comp.dir()).join(rel.replace('/', "\\"));
                    add_log(
                        &mut a,
                        &ui,
                        "main",
                        &format!("Found {}", found.to_string_lossy()),
                        LogType::Debug,
                    );
                    let exe = rel.rsplit('/').next().unwrap_or(rel).to_string();
                    sync_binary_name(&mut a, comp, &exe, &ui);
                }
                None => {
                    missing += 1;
                    add_log(
                        &mut a,
                        &ui,
                        "main",
                        &format!("Component not found: {}", p.to_string_lossy()),
                        LogType::Error,
                    );
                }
            }
        }
        if missing == 0 {
            add_log(
                &mut a,
                &ui,
                "main",
                "All components found",
                LogType::Default,
            );
        }
        add_log(
            &mut a,
            &ui,
            "main",
            "Initializing Modules",
            LogType::Default,
        );
        add_log(
            &mut a,
            &ui,
            "main",
            "Starting Check-Timer",
            LogType::Default,
        );
        add_log(&mut a, &ui, "main", "Control Panel Ready", LogType::Default);
    }

    let app_cb = app.clone();
    let ui_cb = ui.clone();
    main_window.on_start_stop(move |idx| {
        let mut a = app_cb.borrow_mut();
        let i = idx as usize;
        if a.modules[i].running {
            stop_module(&mut a, &ui_cb, i);
        } else {
            start_module(&mut a, &ui_cb, i);
        }
        refresh_and_update(&mut a, &ui_cb);
    });
    let app_cb = app.clone();
    let ui_cb = ui.clone();
    main_window.on_admin(move |idx| {
        let mut a = app_cb.borrow_mut();
        admin_module(&mut a, &ui_cb, idx as usize);
    });
    let app_cb = app.clone();
    let ui_cb = ui.clone();
    main_window
        .on_open_config(move |idx| show_file_window(&app_cb, &ui_cb, "config", idx as usize));
    let app_cb = app.clone();
    let ui_cb = ui.clone();
    main_window.on_open_logs(move |idx| show_file_window(&app_cb, &ui_cb, "logs", idx as usize));
    let app_cb = app.clone();
    let ui_cb = ui.clone();
    main_window.on_do_explorer(move || {
        let mut a = app_cb.borrow_mut();
        let dir = a.basedir.to_string_lossy().to_string();
        add_log(
            &mut a,
            &ui_cb,
            "main",
            &format!("Executing \"{dir}\""),
            LogType::Default,
        );
        shell_open(&dir, "explore");
    });
    let app_cb = app.clone();
    let ui_cb = ui.clone();
    main_window.on_do_settings(move || show_settings_window(&app_cb, &ui_cb));
    let app_cb = app.clone();
    let ui_cb = ui.clone();
    main_window.on_do_updates(move || show_updates(&app_cb, &ui_cb));
    let app_cb = app.clone();
    let ui_cb = ui.clone();
    main_window.on_do_about(move || show_about_window(&app_cb, &ui_cb));
    let app_cb = app.clone();
    let ui_cb = ui.clone();
    main_window.on_do_quit(move || {
        let mut a = app_cb.borrow_mut();
        do_quit(&mut a, &ui_cb);
    });
    let app_cb = app.clone();
    let ui_cb = ui.clone();
    main_window.window().on_close_requested(move || {
        {
            let mut a = app_cb.borrow_mut();
            do_quit(&mut a, &ui_cb);
        }
        CloseRequestResponse::HideWindow
    });

    main_window.show()?;

    // 500 ms timer: TimerUpdateStatus + TimerUpdateNetworking merged.
    let timer = Timer::default();
    let app_t = app.clone();
    let ui_t = ui.clone();
    timer.start(
        TimerMode::Repeated,
        std::time::Duration::from_millis(500),
        move || {
            let mut a = app_t.borrow_mut();
            if a.closing {
                return;
            }
            upd_drain(&mut a, &ui_t);
            refresh_and_update(&mut a, &ui_t);
            if a.log_dirty {
                a.log_dirty = false;
                ui_t.main.invoke_scroll_to_bottom();
            }
        },
    );

    let args: Vec<String> = std::env::args().collect();

    // Headless feed check: xampp-rs --update-check [--json]
    // GUI-subsystem binary: nothing is attached to stdout, so the result goes to
    // the log window and to the shared .log file.
    if args.iter().any(|a| a == "--update-check") {
        let json = args.iter().any(|a| a == "--json");
        let app_t = app.clone();
        let ui_t = ui.clone();
        Timer::single_shot(std::time::Duration::from_millis(900), move || {
            let (bd, allow, line) = {
                let a = app_t.borrow();
                (
                    a.basedir.clone(),
                    a.cfg.upd_allow_major,
                    a.cfg.upd_target_line.clone(),
                )
            };
            add_log(
                &mut app_t.borrow_mut(),
                &ui_t,
                "update",
                "CLI: checking feeds",
                LogType::Info,
            );
            for (comp, r) in update::check_all(&bd, allow, &line) {
                match r {
                    Ok(list) => {
                        if list.is_empty() {
                            add_log(
                                &mut app_t.borrow_mut(),
                                &ui_t,
                                "update",
                                &format!("{}: up to date", comp.label()),
                                LogType::Default,
                            );
                            continue;
                        }
                        for (n, i) in list.iter().enumerate() {
                            let extra = match (i.status.is_empty(), i.note.is_empty()) {
                                (true, _) => i.note.clone(),
                                (_, true) => i.status.clone(),
                                _ => format!("{} | {}", i.status, i.note),
                            };
                            let text = format!(
                                "{}{}: {} -> {}  {}  size={}B  sha256={}{}",
                                if n == 0 { "" } else { "also: " },
                                comp.label(),
                                i.installed,
                                i.available,
                                i.file,
                                i.size,
                                if json { i.sha256.clone() } else { "-".into() },
                                if extra.is_empty() {
                                    String::new()
                                } else {
                                    format!("  [{extra}]")
                                }
                            );
                            add_log(
                                &mut app_t.borrow_mut(),
                                &ui_t,
                                "update",
                                &text,
                                if n == 0 {
                                    LogType::Info
                                } else {
                                    LogType::Default
                                },
                            );
                        }
                    }
                    Err(e) => {
                        let text = format!("{}: feed error: {e}", comp.label());
                        add_log(
                            &mut app_t.borrow_mut(),
                            &ui_t,
                            "update",
                            &text,
                            LogType::Error,
                        );
                    }
                }
            }
            let mut a = app_t.borrow_mut();
            do_quit(&mut a, &ui_t);
        });
    }

    // Headless apply: xampp-rs --update-apply <apache|mysql|php|pma> [line|version]
    if let Some(pos) = args.iter().position(|a| a == "--update-apply") {
        let want = args
            .get(pos + 1)
            .cloned()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let comp = match want.as_str() {
            "apache" => Some(update::Comp::Apache),
            "mysql" | "mariadb" => Some(update::Comp::Mysql),
            "php" => Some(update::Comp::Php),
            "pma" | "phpmyadmin" => Some(update::Comp::Phpmyadmin),
            _ => None,
        };
        let target = args
            .get(pos + 2)
            .cloned()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let app_t = app.clone();
        let ui_t = ui.clone();
        Timer::single_shot(std::time::Duration::from_millis(900), move || {
            let Some(comp) = comp else {
                let mut a = app_t.borrow_mut();
                add_log(
                    &mut a,
                    &ui_t,
                    "update",
                    "--update-apply needs apache|mysql|php|pma",
                    LogType::Error,
                );
                do_quit(&mut a, &ui_t);
                return;
            };
            let (bd, allow, line, keep, limit, ports, name, binary) = {
                let a = app_t.borrow();
                let mi = comp.modules()[0];
                (
                    a.basedir.clone(),
                    a.cfg.upd_allow_major,
                    a.cfg.upd_target_line.clone(),
                    a.cfg.upd_keep_backups.max(0) as usize,
                    a.cfg.upd_data_backup_limit_mb.max(1) as u64,
                    a.modules[mi].check_ports.clone(),
                    a.modules[mi].name,
                    if comp == update::Comp::Mysql {
                        a.cfg.mysql_binary.clone()
                    } else {
                        a.cfg.apache_binary.clone()
                    },
                )
            };
            let list = update::check_all(&bd, allow, &line)
                .into_iter()
                .find(|(c, _)| *c == comp)
                .and_then(|(_, r)| r.ok())
                .unwrap_or_default();
            let info = if target.is_empty() {
                list.first().cloned()
            } else {
                list.iter()
                    .find(|i| {
                        i.available.eq_ignore_ascii_case(&target)
                            || i.available.starts_with(&format!("{target}."))
                            || i.line.eq_ignore_ascii_case(&target)
                    })
                    .cloned()
            };
            let Some(info) = info else {
                let mut a = app_t.borrow_mut();
                let text = if target.is_empty() {
                    "nothing newer to apply".to_string()
                } else {
                    let avail = list
                        .iter()
                        .map(update::target_label)
                        .collect::<Vec<String>>()
                        .join(", ");
                    format!("no candidate matches '{target}' (available: {avail})")
                };
                add_log(&mut a, &ui_t, "update", &text, LogType::Error);
                do_quit(&mut a, &ui_t);
                return;
            };
            add_log(
                &mut app_t.borrow_mut(),
                &ui_t,
                "update",
                &format!(
                    "CLI: applying {} {} -> {}",
                    comp.label(),
                    info.installed,
                    info.available
                ),
                LogType::Info,
            );
            let mut lg = |l: String, warn: bool| {
                add_log(
                    &mut app_t.borrow_mut(),
                    &ui_t,
                    "update",
                    &l,
                    if warn { LogType::Error } else { LogType::Info },
                )
            };
            let r = run_apply(&bd, &info, keep, limit, &ports, name, &binary, &mut lg);
            let mut a = app_t.borrow_mut();
            match r {
                Ok(ap) => {
                    add_log(&mut a, &ui_t, "update", "CLI: apply ok", LogType::Info);
                    sync_binary_name(&mut a, ap.comp, &ap.exe, &ui_t);
                }
                Err(e) => add_log(
                    &mut a,
                    &ui_t,
                    "update",
                    &format!("CLI: apply failed: {e}"),
                    LogType::Error,
                ),
            }
            do_quit(&mut a, &ui_t);
        });
    }

    // Headless restore: xampp-rs --update-restore <apache|mysql|php|pma> [backup_dir]
    if let Some(pos) = args.iter().position(|a| a == "--update-restore") {
        let want = args
            .get(pos + 1)
            .cloned()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let explicit = args.get(pos + 2).cloned();
        let comp = match want.as_str() {
            "apache" => Some(update::Comp::Apache),
            "mysql" | "mariadb" => Some(update::Comp::Mysql),
            "php" => Some(update::Comp::Php),
            "pma" | "phpmyadmin" => Some(update::Comp::Phpmyadmin),
            _ => None,
        };
        let app_t = app.clone();
        let ui_t = ui.clone();
        Timer::single_shot(std::time::Duration::from_millis(900), move || {
            let Some(comp) = comp else {
                let mut a = app_t.borrow_mut();
                add_log(
                    &mut a,
                    &ui_t,
                    "update",
                    "--update-restore needs apache|mysql|php|pma [backup_dir]",
                    LogType::Error,
                );
                do_quit(&mut a, &ui_t);
                return;
            };
            let (bd, ports, name, binary) = {
                let a = app_t.borrow();
                let mi = comp.modules()[0];
                (
                    a.basedir.clone(),
                    a.modules[mi].check_ports.clone(),
                    a.modules[mi].name,
                    if comp == update::Comp::Mysql {
                        a.cfg.mysql_binary.clone()
                    } else {
                        a.cfg.apache_binary.clone()
                    },
                )
            };
            let backup = match explicit {
                Some(p) => PathBuf::from(p),
                None => match update::find_backup(&bd, comp) {
                    Some(p) => p,
                    None => {
                        let mut a = app_t.borrow_mut();
                        add_log(
                            &mut a,
                            &ui_t,
                            "update",
                            "no backup of this component under .backup",
                            LogType::Error,
                        );
                        do_quit(&mut a, &ui_t);
                        return;
                    }
                },
            };
            add_log(
                &mut app_t.borrow_mut(),
                &ui_t,
                "update",
                &format!("CLI: restoring {} from {}", comp.label(), backup.display()),
                LogType::Info,
            );
            let mut lg = |l: String, warn: bool| {
                add_log(
                    &mut app_t.borrow_mut(),
                    &ui_t,
                    "update",
                    &l,
                    if warn { LogType::Error } else { LogType::Info },
                )
            };
            let r = run_restore(&bd, comp, &backup, &ports, name, &binary, &mut lg);
            let mut a = app_t.borrow_mut();
            match r {
                Ok(exe) => {
                    add_log(
                        &mut a,
                        &ui_t,
                        "update",
                        &format!("CLI: restore ok (daemon {exe})"),
                        LogType::Info,
                    );
                    sync_binary_name(&mut a, comp, &exe, &ui_t);
                }
                Err(e) => add_log(
                    &mut a,
                    &ui_t,
                    "update",
                    &format!("CLI: files restored, but the module did not start: {e}"),
                    LogType::Error,
                ),
            }
            do_quit(&mut a, &ui_t);
        });
    }

    // Hidden test mode: xampp-rs --test-cycle <apache|mysql|both> [hold_secs]
    if let Some(pos) = args.iter().position(|a| a == "--test-cycle") {
        let target = args.get(pos + 1).cloned().unwrap_or_else(|| "both".into());
        let hold: u64 = args.get(pos + 2).and_then(|s| s.parse().ok()).unwrap_or(6);
        let idxs: Vec<usize> = match target.as_str() {
            "apache" => vec![0],
            "mysql" => vec![1],
            _ => vec![0, 1],
        };
        let app_t = app.clone();
        let ui_t = ui.clone();
        let idxs2 = idxs.clone();
        Timer::single_shot(std::time::Duration::from_millis(800), move || {
            let mut a = app_t.borrow_mut();
            for &i in &idxs2 {
                start_module(&mut a, &ui_t, i);
            }
        });
        let app_t = app.clone();
        let ui_t = ui.clone();
        let idxs3 = idxs.clone();
        Timer::single_shot(
            std::time::Duration::from_millis(800 + hold * 1000),
            move || {
                let mut a = app_t.borrow_mut();
                for &i in &idxs3 {
                    let name = a.modules[i].name;
                    if a.modules[i].running {
                        add_log(
                            &mut a,
                            &ui_t,
                            "main",
                            &format!("TEST: {name} is running, stopping it"),
                            LogType::Info,
                        );
                        stop_module(&mut a, &ui_t, i);
                    } else {
                        add_log(
                            &mut a,
                            &ui_t,
                            "main",
                            &format!("TEST FAIL: {name} never started"),
                            LogType::Error,
                        );
                    }
                }
            },
        );
        let app_t = app.clone();
        let ui_t = ui.clone();
        Timer::single_shot(
            std::time::Duration::from_millis(800 + hold * 1000 + 5000),
            move || {
                let mut a = app_t.borrow_mut();
                for &i in &idxs {
                    let name = a.modules[i].name;
                    if a.modules[i].running {
                        add_log(
                            &mut a,
                            &ui_t,
                            "main",
                            &format!("TEST FAIL: {name} still running after stop"),
                            LogType::Error,
                        );
                    } else {
                        add_log(
                            &mut a,
                            &ui_t,
                            "main",
                            &format!("TEST PASS: {name} stopped cleanly"),
                            LogType::Info,
                        );
                    }
                }
                do_quit(&mut a, &ui_t);
            },
        );
    }

    // Hidden maintenance: xampp-rs --patch-compat
    // Re-applies the Apache/PHP compatibility fixes to the current tree, then exits.
    if args.iter().any(|a| a == "--patch-compat") {
        let app_t = app.clone();
        let ui_t = ui.clone();
        Timer::single_shot(std::time::Duration::from_millis(500), move || {
            let mut a = app_t.borrow_mut();
            let bd = a.basedir.clone();
            {
                let mut lg = |l: String, warn: bool| {
                    add_log(
                        &mut a,
                        &ui_t,
                        "update",
                        &l,
                        if warn { LogType::Error } else { LogType::Info },
                    )
                };
                update::patch_compat(&bd, &mut lg);
            }
            add_log(&mut a, &ui_t, "update", "compat patch finished", LogType::Info);
            do_quit(&mut a, &ui_t);
        });
    }

    slint::run_event_loop()?;
    Ok(())
}
