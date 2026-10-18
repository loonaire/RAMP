mod config;
mod http;
mod install;
mod netstat;
mod pe;
mod procs;
mod update;

use slint::{
    CloseRequestResponse, ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
};
use windows::Win32::System::SystemInformation::GetLocalTime;
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcessId, OpenProcess, TerminateProcess, CREATE_NEW_CONSOLE,
    NORMAL_PRIORITY_CLASS, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_TERMINATE,
    STARTF_USESHOWWINDOW, STARTUPINFOW,
};
use windows::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForSystem};
use windows::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::{
    CallWindowProcW, DefWindowProcW, EnumWindows, GetClassNameW, GetClientRect, GetSystemMetrics,
    GetWindow, GetWindowLongPtrW, GetWindowRect, GetWindowTextW, GetWindowThreadProcessId,
    IsWindowVisible, SetWindowLongPtrW, SetWindowPos, SHOW_WINDOW_CMD, SM_CXSCREEN, SM_CYSCREEN,
    SPI_GETWORKAREA, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER, SW_HIDE, SW_SHOW,
    SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, WM_WINDOWPOSCHANGING, WINDOWPOS, WNDPROC,
    WS_BORDER, WS_CAPTION, WS_CLIPSIBLINGS, WS_EX_ACCEPTFILES, WS_EX_WINDOWEDGE, WS_SYSMENU,
    GWLP_HWNDPARENT, GWLP_WNDPROC, GW_OWNER, SystemParametersInfoW,
};

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
    dep_win: Option<Rc<DepWindow>>,
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
        .unwrap_or_else(|| "ramp".into())
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

// Sub-window anchoring: Slint 1.18 exposes none of this, so it is plain Win32.
// A sub-window is made an OWNED window of the panel (GWLP_HWNDPARENT): no taskbar
// button, stays above it, hides together with it. Its position is pinned by a
// WM_WINDOWPOSCHANGING subclass that rewrites every proposed move back to the
// coordinates captured when the window first appeared, which makes title-bar
// dragging inert. Resizing is already prevented at the .slint level (fixed
// width/height, min == max).
static MAIN_HWND: std::sync::OnceLock<std::sync::Mutex<isize>> = std::sync::OnceLock::new();

fn main_hwnd() -> Option<isize> {
    let h = *MAIN_HWND
        .get_or_init(|| std::sync::Mutex::new(0))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    (h != 0).then_some(h)
}

fn set_main_hwnd(h: isize) {
    *MAIN_HWND
        .get_or_init(|| std::sync::Mutex::new(0))
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = h;
}

unsafe extern "system" fn collect_self_wnd(hwnd: HWND, l: LPARAM) -> BOOL {
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == GetCurrentProcessId() && IsWindowVisible(hwnd).as_bool() {
        let v = &mut *(l.0 as *mut Vec<isize>);
        v.push(hwnd.0 as isize);
    }
    true.into()
}

/// HWNDs of this process's visible top-level windows.
fn self_windows() -> Vec<isize> {
    let mut v: Vec<isize> = Vec::new();
    unsafe {
        let _ = EnumWindows(Some(collect_self_wnd), LPARAM(&mut v as *mut _ as isize));
    }
    v
}

// HWND -> ((pinned x, pinned y), original WNDPROC). Backs the classic
// GWLP_WNDPROC hook below; the hook lives for the whole process lifetime.
static PIN_MAP: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<isize, ([i32; 2], isize)>>,
> = std::sync::OnceLock::new();

unsafe extern "system" fn pin_pos_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let map = PIN_MAP.get_or_init(Default::default);
    let entry = map
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(hwnd.0 as isize))
        .copied();
    if let Some((pin, orig)) = entry {
        if msg == WM_WINDOWPOSCHANGING {
            let pos = &mut *(lparam.0 as *mut WINDOWPOS);
            pos.x = pin[0];
            pos.y = pin[1];
        }
        let orig: WNDPROC = Some(core::mem::transmute(orig));
        return CallWindowProcW(orig, hwnd, msg, wparam, lparam);
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// HWNDs already anchored, so a singleton re-show is never hooked twice.
static ANCHORED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<isize>>> =
    std::sync::OnceLock::new();

/// Window titles used for anchoring/tests; must match the `title:` literals in
/// ui/main.slint (Slint does not expose a getter for the window title).
const TITLE_MAIN: &str = "RAMP Control Panel";
const TITLE_SETTINGS: &str = "Settings";
const TITLE_UPDATES: &str = "Component Updates";
const TITLE_ABOUT: &str = "About RAMP Control Panel";
const TITLE_DEPS: &str = "Missing libraries";

/// The one page Microsoft keeps current for the x64 VC++ runtime.
const VC_REDIST_X64: &str = "https://aka.ms/vs/17/release/vc_redist.x64.exe";
const TITLE_FILES: &str = "RAMP Files";

/// Show a sub-window, then anchor it on the main window (owned: no taskbar
/// button; position pinned). Slint maps the native HWND only after show()
/// returns, so anchoring runs on a retry timer that matches the window by its
/// title.
fn show_and_anchor<W: ComponentHandle>(win: &Rc<W>, title: &str) {
    pre_center(win, title);
    let _ = win.window().show();
    anchor_by_title(title.to_string(), 10);
}

fn find_win_by_title(title: &str, skip: &[isize]) -> Option<isize> {
    let mut tb = [0u16; 128];
    self_windows().into_iter().find(|h| {
        if *h == 0 || skip.contains(h) {
            return false;
        }
        unsafe {
            let tl = GetWindowTextW(HWND(*h as *mut core::ffi::c_void), &mut tb) as usize;
            String::from_utf16_lossy(&tb[..tl.min(128)]) == title
        }
    })
}

/// Primary monitor work area in physical pixels (taskbar excluded); falls
/// back to the whole screen when the query fails.
fn work_area() -> (f64, f64, f64, f64) {
    unsafe {
        let mut wa = RECT::default();
        if SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some(&mut wa as *mut RECT as *mut core::ffi::c_void),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
        .is_ok()
        {
            (
                f64::from(wa.right - wa.left),
                f64::from(wa.bottom - wa.top),
                f64::from(wa.left),
                f64::from(wa.top),
            )
        } else {
            (
                f64::from(GetSystemMetrics(SM_CXSCREEN)),
                f64::from(GetSystemMetrics(SM_CYSCREEN)),
                0.0,
                0.0,
            )
        }
    }
}

/// Centered top-left for the window's *outer* rect (GetWindowRect space, so
/// title bar and invisible DWM borders are visually centered too).
fn center_target(hwnd: HWND) -> Option<(i32, i32)> {
    let mut r = RECT::default();
    unsafe { GetWindowRect(hwnd, &mut r).ok()? };
    let w = f64::from(r.right - r.left);
    let h = f64::from(r.bottom - r.top);
    if w <= 0.0 || h <= 0.0 {
        return None;
    }
    let (aw, ah, ox, oy) = work_area();
    Some((
        (ox + (aw - w) / 2.0) as i32,
        (oy + (ah - h) / 2.0) as i32,
    ))
}

fn center_hwnd(hwnd: HWND) -> Option<(i32, i32)> {
    let (x, y) = center_target(hwnd)?;
    unsafe {
        let _ = SetWindowPos(hwnd, None, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    Some((x, y))
}

/// Frame-vs-client delta (title bar + borders + menu bar, physical px) for
/// the windows winit creates: Slint marks fixed-size windows non-resizable,
/// so the style is WS_CAPTION|WS_BORDER|WS_CLIPSIBLINGS|WS_SYSMENU (no
/// invisible DWM resize border). The main window also carries a native menu
/// bar (bmenu). Computed from system metrics; each mapped window title then
/// calibrates the exact values (FDELTA).
fn est_frame_delta(menu: bool) -> (i32, i32) {
    unsafe {
        let mut r = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        if AdjustWindowRectExForDpi(
            &mut r,
            WS_CAPTION | WS_BORDER | WS_CLIPSIBLINGS | WS_SYSMENU,
            menu,
            WS_EX_WINDOWEDGE | WS_EX_ACCEPTFILES,
            GetDpiForSystem(),
        )
        .is_ok()
        {
            (r.right - r.left, r.bottom - r.top)
        } else {
            if menu {
                (16, 49) // caption + menu bar at 100% DPI
            } else {
                (16, 39)
            }
        }
    }
}

static FDELTA: std::sync::OnceLock<std::sync::Mutex<HashMap<String, (i32, i32)>>> =
    std::sync::OnceLock::new();

/// Declared client sizes from ui/main.slint (physical px at 100% DPI; the
/// main window's excludes the menu bar, like Slint's size() does). Used as a
/// fallback because Slint's window().size() reads 0x0 before the first
/// show(). The anchored-window test keeps these in sync with the .slint.
fn declared_size(title: &str) -> Option<(i32, i32)> {
    match title {
        TITLE_MAIN => Some((690, 460)),
        TITLE_SETTINGS => Some((480, 440)),
        TITLE_UPDATES => Some((680, 430)),
        TITLE_FILES => Some((520, 380)),
        TITLE_ABOUT => Some((340, 230)),
        TITLE_DEPS => Some((480, 220)),
        _ => None,
    }
}

/// Refine the frame delta per window title with the rects of a mapped
/// window, so re-shown windows land exactly centered on the first mapping.
fn calibrate_frame_delta(hwnd: HWND, title: &str) {
    let map = FDELTA.get_or_init(Default::default);
    let mut g = map.lock().unwrap_or_else(|e| e.into_inner());
    if g.contains_key(title) {
        return;
    }
    unsafe {
        let mut wr = RECT::default();
        let mut cr = RECT::default();
        if GetWindowRect(hwnd, &mut wr).is_ok() && GetClientRect(hwnd, &mut cr).is_ok() {
            let dx = (wr.right - wr.left) - (cr.right - cr.left);
            let dy = (wr.bottom - wr.top) - (cr.bottom - cr.top);
            if dx > 0 && dy > 0 {
                let est = est_frame_delta(title == TITLE_MAIN);
                eprintln!(
                    "frame delta \"{title}\" calibrated ({dx},{dy}), metrics estimate ({},{})",
                    est.0, est.1
                );
                g.insert(title.to_string(), (dx, dy));
            }
        }
    }
}

/// Put the window at its centered spot *before* show(): Slint keeps the
/// position in the pending window attributes and winit applies it (SetWindowPos
/// at WM_CREATE, outer-rect space) before the window is ever revealed, so the
/// window never visibly jumps from its default spot to the center.
fn pre_center<W: ComponentHandle>(win: &Rc<W>, title: &str) {
    let (aw, ah, ox, oy) = work_area();
    let cs = win.window().size();
    let (cw, ch) = if cs.width > 0 && cs.height > 0 {
        (cs.width as i32, cs.height as i32)
    } else {
        match declared_size(title) {
            Some(s) => s,
            None => return,
        }
    };
    let (dx, dy) = FDELTA
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(title)
        .copied()
        .unwrap_or_else(|| est_frame_delta(title == TITLE_MAIN));
    let x = (ox + (aw - (f64::from(cw) + f64::from(dx))) / 2.0) as i32;
    let y = (oy + (ah - (f64::from(ch) + f64::from(dy))) / 2.0) as i32;
    win.window().set_position(slint::PhysicalPosition::new(x, y));
    eprintln!(
        "pre-center \"{title}\" client={cw}x{ch} frame_delta=({dx},{dy}) -> ({x},{y})",
    );
}

/// Center the main window once its native window is mapped (matched by title
/// so the winit helper windows are never moved instead).
fn center_main_when_mapped(title: String, retries: u8) {
    Timer::single_shot(std::time::Duration::from_millis(60), move || {
        if let Some(h) = find_win_by_title(&title, &[]) {
            if let Some((x, y)) = center_hwnd(HWND(h as *mut core::ffi::c_void)) {
                calibrate_frame_delta(HWND(h as *mut core::ffi::c_void), &title);
                eprintln!("centered main \"{title}\" 0x{h:x} at ({x},{y})");
                return;
            }
        }
        if retries > 0 {
            center_main_when_mapped(title, retries - 1);
        }
    });
}

fn fix_main_hwnd(title: String, retries: u8) {
    Timer::single_shot(std::time::Duration::from_millis(60), move || {
        if let Some(h) = find_win_by_title(&title, &[]) {
            set_main_hwnd(h);
            eprintln!("main HWND fixed = 0x{h:x} (title \"{title}\")");
        } else if retries > 0 {
            fix_main_hwnd(title, retries - 1);
        }
    });
}

fn anchor_by_title(title: String, retries: u8) {
    Timer::single_shot(std::time::Duration::from_millis(60), move || {
        let Some(owner) = main_hwnd() else {
            eprintln!("anchor: MAIN_HWND unset, skipped");
            return;
        };
        let mut tb = [0u16; 128];
        let mut found: Option<isize> = None;
        for h in self_windows() {
            if h == owner {
                continue;
            }
            unsafe {
                let tl = GetWindowTextW(HWND(h as *mut core::ffi::c_void), &mut tb) as usize;
                if String::from_utf16_lossy(&tb[..tl.min(128)]) == title {
                    found = Some(h);
                }
            }
            if found.is_some() {
                break;
            }
        }
        let Some(h) = found else {
            if retries > 0 {
                anchor_by_title(title, retries - 1);
            } else {
                eprintln!("anchor: no HWND ever matched title \"{title}\"");
            }
            return;
        };
        let hwnd = HWND(h as *mut core::ffi::c_void);
        if ANCHORED
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&h)
        {
            // Re-show of an already hooked window: update the pin *before* the
            // move, else the hook would rewrite the move back to the old pin.
            if let Some((x, y)) = center_target(hwnd) {
                {
                    let pm = PIN_MAP.get_or_init(Default::default);
                    let mut g = pm.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(&(_, orig)) = g.get(&h) {
                        g.insert(h, ([x, y], orig));
                    }
                }
                unsafe {
                    let _ = SetWindowPos(
                        hwnd,
                        None,
                        x,
                        y,
                        0,
                        0,
                        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
                    );
                }
                eprintln!("re-center: \"{title}\" hwnd=0x{h:x} at ({x},{y})");
            }
            return;
        }
        // First mapping: center before the hook exists, so the pin below
        // captures the centered position.
        let _ = center_hwnd(hwnd);
        calibrate_frame_delta(hwnd, &title);
        ANCHORED
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(h);
        unsafe {
            let prev = SetWindowLongPtrW(hwnd, GWLP_HWNDPARENT, owner);
            let mut rc = RECT::default();
            if GetWindowRect(hwnd, &mut rc).is_ok() {
                // Never removed on purpose: the hook outlives the window.
                let orig = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, pin_pos_proc as *const () as isize);
                if orig != 0 {
                    PIN_MAP
                        .get_or_init(Default::default)
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(h, ([rc.left, rc.top], orig));
                    eprintln!(
                        "anchor: \"{title}\" hwnd=0x{h:x} owner=0x{owner:x} prev_owner=0x{prev:x} pin=({},{})",
                        rc.left, rc.top
                    );
                } else {
                    eprintln!("anchor: hwnd=0x{h:x} WNDPROC hook failed");
                }
            }
        }
    });
}

/// Blocking start used by the updater: same command lines as start_module(), but
/// it waits until the process really owns a listening socket instead of leaving
/// that to the 250 ms timer. A swap is only trustworthy once the new build has
/// been shown to boot.
fn start_module_blocking(basedir: &Path, name: &str, binary: &str) -> Result<(), String> {
    // A finished install deletes the scratch folder tmp/, and my.ini/php.ini
    // point their tmpdir, session.save_path and upload_tmp_dir right at it.
    update::ensure_runtime_dirs(basedir, &mut |_, _| {});
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
    /// First-run bootstrap: the server binaries the install ended up with.
    BootDone(Result<(String, String), String>),
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

/// First run of a fresh package: install everything in the background. Only a
/// completely empty tree triggers this; a package that is missing a single
/// component gets a hint instead, because removing one on purpose is a normal
/// thing to do. The worker talks through the updater's queue, so the log panel
/// follows along and the panel stays usable.
fn start_first_run(app: &AppRc, _ui: &Ui) {
    let (bd, o) = {
        let mut a = app.borrow_mut();
        if a.upd_busy {
            return;
        }
        let miss = install::missing(&a.basedir);
        let repair = miss.is_empty() && install::needs_repair(&a.basedir);
        if miss.is_empty() && !repair {
            return;
        }
        if repair {
            add_log(
                &mut a,
                _ui,
                "update",
                "this installation lives somewhere else than its configuration says: re-anchoring it",
                LogType::Info,
            );
        }
        if miss.len() < 4 {
            add_log(
                &mut a,
                _ui,
                "update",
                &format!(
                    "missing component(s): {}. Reinstall them from the update window, or run ramp --first-run.",
                    miss.iter().map(|c| c.label()).collect::<Vec<_>>().join(", ")
                ),
                LogType::Error,
            );
            return;
        }
        let o = install::Opts {
            apache_port: a.cfg.apache_port,
            mysql_port: a.cfg.mysql_port,
            target_line: a.cfg.upd_target_line.clone(),
            verify: !repair,
        };
        (a.basedir.clone(), o)
    };
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let mut a = app.borrow_mut();
        a.upd_busy = true;
        a.upd_rx = Some(rx);
    }
    if let Some(w) = app.borrow().upd_win.clone() {
        w.set_busy(true);
        w.set_status("Installing the components...".into());
    }
    add_log(
        &mut app.borrow_mut(),
        _ui,
        "update",
        "First run: downloading and installing MariaDB, PHP, Apache and phpMyAdmin. This takes a few minutes...",
        LogType::Info,
    );
    std::thread::spawn(move || {
        let mut lg = |line: String, warn: bool| {
            let _ = tx.send(UpdMsg::Log(line, warn));
        };
        let mut pg = |_done: u64, _total: u64| {};
        let r = install::bootstrap(&bd, &o, &mut lg, &mut pg)
            .map(|b| (b.apache_exe, b.mysql_exe));
        let _ = tx.send(UpdMsg::BootDone(r));
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
        &format!("BinaryNames in ramp.ini: {old} -> {exe}"),
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
            UpdMsg::BootDone(r) => {
                pending = false;
                app.upd_busy = false;
                match r {
                    Ok((apache_exe, mysql_exe)) => {
                        add_log(
                            app,
                            ui,
                            "update",
                            "Installation complete. Apache and MariaDB can now be started from the panel.",
                            LogType::Info,
                        );
                        sync_binary_name(app, update::Comp::Apache, &apache_exe, ui);
                        sync_binary_name(app, update::Comp::Mysql, &mysql_exe, ui);
                    }
                    Err(e) => add_log(
                        app,
                        ui,
                        "update",
                        &format!("Installation failed: {e}"),
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
    win.set_app_version(format!("Version RAMP v{}", env!("CARGO_PKG_VERSION")).into());
    show_and_anchor(&win, TITLE_ABOUT);
}

/// ---------------------------------------------------------------- dependencies

/// True for the libraries the Visual C++ Redistributable owns: those are the
/// ones a plain Windows install may genuinely lack.
fn is_vc_runtime(dll: &str) -> bool {
    let d = dll.to_ascii_lowercase();
    d.starts_with("vcruntime")
        || d.starts_with("msvcp")
        || d.starts_with("vccorlib")
        || d.starts_with("msvcr")
        || d.starts_with("ucrtbase")
}

/// Direct imports of the binaries this panel is about to start, that exist
/// neither in the package nor in System32. Api-set entries (`api-ms-win-*`) are
/// resolved by the loader itself and are not files, so they stay out of the way.
fn dependency_gaps(basedir: &Path) -> Vec<(String, String)> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| String::from("C:\\Windows"));
    let mut dirs: Vec<PathBuf> = vec![
        basedir.join("apache\\bin"),
        basedir.join("php"),
        basedir.join("mysql\\bin"),
        basedir.to_path_buf(),
        PathBuf::from(sysroot).join("System32"),
    ];
    dirs.retain(|d| d.is_dir());

    let (rt, md) = install::php_dlls(basedir);
    let wanted: [(&str, PathBuf); 5] = [
        ("apache\\bin\\httpd.exe", basedir.join("apache\\bin\\httpd.exe")),
        ("php\\php.exe", basedir.join("php\\php.exe")),
        (
            "php\\<runtime>",
            basedir.join(format!("php\\{rt}.dll")),
        ),
        (
            "php\\<apache module>",
            basedir.join(format!("php\\{md}.dll")),
        ),
        ("mysql\\bin\\mariadbd.exe", basedir.join("mysql\\bin\\mariadbd.exe")),
    ];
    let mut gaps: Vec<(String, String)> = Vec::new();
    for (who, path) in wanted {
        if !path.is_file() {
            continue;
        }
        for dll in pe::imports(&path) {
            let base = dll
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(&dll)
                .to_ascii_lowercase();
            if base.is_empty() || base.starts_with("api-ms-win") || base.starts_with("ext-ms-") {
                continue;
            }
            if dirs.iter().any(|d| d.join(&base).is_file()) {
                continue;
            }
            if !gaps.iter().any(|(n, _)| *n == base) {
                gaps.push((base, who.to_string()));
            }
        }
    }
    gaps
}

/// Tell the user about it instead of letting Apache die in silence: the panel
/// cannot install a system runtime itself, but it can hand over the link.
fn check_dependencies(app: &AppRc, ui: &Ui) {
    let gaps = {
        let a = app.borrow();
        dependency_gaps(&a.basedir)
    };
    if gaps.is_empty() {
        return;
    }
    let list = gaps
        .iter()
        .map(|(d, w)| format!("{d} ({w})"))
        .collect::<Vec<_>>()
        .join(", ");
    add_log(
        &mut app.borrow_mut(),
        ui,
        "main",
        &format!("missing libraries: {list}"),
        LogType::Error,
    );
    let vc = gaps.iter().any(|(d, _)| is_vc_runtime(d));
    show_dep_window(app, &gaps, vc);
}

fn show_dep_window(app: &AppRc, gaps: &[(String, String)], vc: bool) {
    let win = {
        let mut a = app.borrow_mut();
        if let Some(w) = a.dep_win.clone() {
            w
        } else {
            let Ok(w) = DepWindow::new() else { return };
            let w = Rc::new(w);
            let wc = w.clone();
            w.on_close_it(move || {
                let _ = wc.hide();
            });
            w.window()
                .on_close_requested(|| CloseRequestResponse::HideWindow);
            a.dep_win = Some(w.clone());
            w
        }
    };
    let names: Vec<&str> = gaps.iter().take(4).map(|(d, _)| d.as_str()).collect();
    let joined = names.join(", ");
    let more = if gaps.len() > 4 {
        format!(" and {} more", gaps.len() - 4)
    } else {
        String::new()
    };
    let who = gaps
        .first()
        .map(|(_, w)| w.as_str())
        .unwrap_or("a component");
    if vc {
        win.set_headline("A Windows component is missing".into());
        win.set_details(
            format!(
                "{joined}{more} is needed by {who}, and is neither in this package nor in Windows. \
                 Those libraries belong to the Microsoft Visual C++ Redistributable (x64): install \
                 it, then start RAMP again. Apache and PHP will not run without it."
            )
            .into(),
        );
        win.set_link_text("Download the Visual C++ Redistributable (x64)".into());
    } else {
        win.set_headline(format!("A library is missing: {joined}").into());
        win.set_details(
            format!(
                "{joined}{more}, needed by {who}, cannot be found in this package or in Windows. \
                 That installation is incomplete: open the update window and reinstall the component."
            )
            .into(),
        );
        win.set_link_text("".into());
    }
    let url = if vc { VC_REDIST_X64.to_string() } else { String::new() };
    win.on_open_link(move || {
        if !url.is_empty() {
            let _ = shell_open(&url, "open");
        }
    });
    show_and_anchor(&win, TITLE_DEPS);
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
    show_and_anchor(&win, TITLE_UPDATES);
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
    // The scratch folder tmp/ is deleted when an install finishes; the server
    // about to start needs it (my.ini tmpdir, php.ini session/upload dirs).
    let bd = app.basedir.clone();
    update::ensure_runtime_dirs(&bd, &mut |l, warn| {
        add_log(
            app,
            ui,
            "main",
            &l,
            if warn { LogType::Error } else { LogType::Debug },
        )
    });
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
    let mut widest = 0usize;
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
        let ports = module_ports(app, m);
        widest = widest.max(ports.chars().count());
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
                port_text: ports.into(),
                status_brush: brush(bg),
                status_text: label.into(),
                status_fg: brush(fg),
                action_text: if m.running { "Stop" } else { "Start" }.into(),
                admin_enabled: m.running,
                start_enabled: true,
            },
        );
    }
    // A 12px digit is about 6.8px wide; 56px is the "PORT(S)" header, so the
    // column never gets narrower than its own label. The status pill then sits
    // right behind the numbers instead of 70px further along the row.
    let want = (12.0 + widest as f32 * 6.8).clamp(56.0, 150.0);
    if ui.main.get_port_col_width() != want {
        ui.main.set_port_col_width(want);
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
    show_and_anchor(&win, TITLE_FILES);
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
    show_and_anchor(&win, TITLE_SETTINGS);
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
    // The project was named xampp-rs before becoming RAMP: carry the old
    // per-exe config and log over when running under the new binary name.
    if stem != "xampp-rs" {
        let legacy_ini = basedir.join("xampp-rs.ini");
        if !ini_path.exists() && legacy_ini.exists() {
            let _ = std::fs::rename(&legacy_ini, &ini_path);
        }
        let legacy_log = basedir.join("xampp-rs.log");
        if !log_path.exists() && legacy_log.exists() {
            let _ = std::fs::rename(&legacy_log, &log_path);
        }
    }
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
        dep_win: None,
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
            &format!(
                "Control Panel Version: RAMP v{}",
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

    // Map directly at the centered position (see pre_center); the retry timer
    // below only verifies/refines, so the window never visibly jumps.
    pre_center(&main_window, TITLE_MAIN);
    main_window.show()?;
    // Remember the main window's HWND: every sub-window is anchored onto it.
    // Slint maps the native HWND shortly after show() and the process also owns
    // helper windows with empty titles, so match on the Slint title and fix up
    // on a retry timer when that match is not immediate.
    let mtitle = TITLE_MAIN.to_string();
    unsafe {
        for h in self_windows() {
            let hwnd = HWND(h as *mut core::ffi::c_void);
            let mut tb = [0u16; 128];
            let tl = GetWindowTextW(hwnd, &mut tb) as usize;
            let mut cl = [0u16; 64];
            let cll = GetClassNameW(hwnd, &mut cl) as usize;
            let mut rc = RECT::default();
            let _ = GetWindowRect(hwnd, &mut rc);
            eprintln!(
                "topwin 0x{h:x} class=\"{}\" title=\"{}\" rect=({},{},{},{})",
                String::from_utf16_lossy(&cl[..cll.min(64)]),
                String::from_utf16_lossy(&tb[..tl.min(128)]),
                rc.left,
                rc.top,
                rc.right,
                rc.bottom
            );
        }
    }
    let direct = find_win_by_title(&mtitle, &[]);
    match direct.or_else(|| self_windows().first().copied()) {
        Some(h) => {
            eprintln!("main HWND = 0x{h:x} (title \"{mtitle}\")");
            set_main_hwnd(h);
        }
        None => eprintln!("main HWND not found after show()"),
    }
    if direct.is_none() {
        fix_main_hwnd(mtitle, 10);
    }
    // Center the main window once its native window is actually mapped.
    center_main_when_mapped(TITLE_MAIN.to_string(), 15);

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

    // A completely empty package installs itself once the window is up, unless
    // a CLI mode is driving.
    if args.len() <= 1 {
        let app_dp = app.clone();
        let ui_dp = ui.clone();
        Timer::single_shot(std::time::Duration::from_millis(400), move || {
            check_dependencies(&app_dp, &ui_dp);
        });
        let app_fr = app.clone();
        let ui_fr = ui.clone();
        Timer::single_shot(std::time::Duration::from_millis(800), move || {
            start_first_run(&app_fr, &ui_fr);
        });
    }

    // Hidden test mode: ramp --deps-check (report what will not load, then leave)
    if args.iter().any(|a| a == "--deps-check") {
        let app_t = app.clone();
        let ui_t = ui.clone();
        Timer::single_shot(std::time::Duration::from_millis(600), move || {
            let gaps = {
                let a = app_t.borrow();
                dependency_gaps(&a.basedir)
            };
            let mut a = app_t.borrow_mut();
            if gaps.is_empty() {
                add_log(
                    &mut a,
                    &ui_t,
                    "main",
                    "dependency check: every library resolved",
                    LogType::Info,
                );
            } else {
                let list = gaps
                    .iter()
                    .map(|(d, w)| format!("{d} ({w})"))
                    .collect::<Vec<_>>()
                    .join(", ");
                add_log(
                    &mut a,
                    &ui_t,
                    "main",
                    &format!("dependency check: {} unresolved: {list}", gaps.len()),
                    LogType::Error,
                );
            }
            do_quit(&mut a, &ui_t);
        });
    }

    // Headless first-run install: ramp --first-run [--no-verify]
    if args.iter().any(|a| a == "--first-run") {
        let verify = !args.iter().any(|a| a == "--no-verify");
        let app_t = app.clone();
        let ui_t = ui.clone();
        Timer::single_shot(std::time::Duration::from_millis(900), move || {
            let (bd, o) = {
                let a = app_t.borrow();
                (
                    a.basedir.clone(),
                    install::Opts {
                        apache_port: a.cfg.apache_port,
                        mysql_port: a.cfg.mysql_port,
                        target_line: a.cfg.upd_target_line.clone(),
                        verify,
                    },
                )
            };
            let mut last = 0u64;
            let mut lg = |l: String, warn: bool| {
                add_log(
                    &mut app_t.borrow_mut(),
                    &ui_t,
                    "update",
                    &l,
                    if warn { LogType::Error } else { LogType::Info },
                );
            };
            let mut pg = |done: u64, total: u64| {
                if total == 0 {
                    return;
                }
                let pct = done * 100 / total;
                if pct / 20 != last / 20 {
                    last = pct;
                    add_log(
                        &mut app_t.borrow_mut(),
                        &ui_t,
                        "update",
                        &format!("download {pct}%"),
                        LogType::Default,
                    );
                }
            };
            let r = install::bootstrap(&bd, &o, &mut lg, &mut pg);
            let mut a = app_t.borrow_mut();
            match r {
                Ok(b) => {
                    add_log(
                        &mut a,
                        &ui_t,
                        "update",
                        &format!("CLI: installed, binaries {} / {}", b.apache_exe, b.mysql_exe),
                        LogType::Info,
                    );
                    sync_binary_name(&mut a, update::Comp::Apache, &b.apache_exe, &ui_t);
                    sync_binary_name(&mut a, update::Comp::Mysql, &b.mysql_exe, &ui_t);
                }
                Err(e) => add_log(
                    &mut a,
                    &ui_t,
                    "update",
                    &format!("CLI: install failed: {e}"),
                    LogType::Error,
                ),
            }
            do_quit(&mut a, &ui_t);
        });
    }

    // Headless feed check: ramp --update-check [--json]
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

    // Headless apply: ramp --update-apply <apache|mysql|php|pma> [line|version]
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

    // Headless restore: ramp --update-restore <apache|mysql|php|pma> [backup_dir]
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

    // Hidden test mode: ramp --test-cycle <apache|mysql|both> [hold_secs]
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

    // Hidden maintenance: ramp --patch-compat
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
    
    // Hidden test mode: ramp --dialog-check [hold_secs]
    // Opens every sub-window, then asserts each is owned by the main window
    // (no taskbar button) and position-locked (proposed moves rejected).
    if let Some(pos) = args.iter().position(|a| a == "--dialog-check") {
            let hold: u64 = args.get(pos + 1).and_then(|s| s.parse().ok()).unwrap_or(3);
            let app_t = app.clone();
            let ui_t = ui.clone();
            Timer::single_shot(std::time::Duration::from_millis(900), move || {
        show_settings_window(&app_t, &ui_t);
        show_updates(&app_t, &ui_t);
        show_about_window(&app_t, &ui_t);
        show_file_window(&app_t, &ui_t, "config", 0);
        show_dep_window(
            &app_t,
            &[("vcruntime140.dll".to_string(), "apache\\bin\\httpd.exe".to_string())],
            true,
        );
            });
            let app_t = app.clone();
            let ui_t = ui.clone();
            Timer::single_shot(
        std::time::Duration::from_millis(900 + hold * 1000),
        move || {
            let mut a = app_t.borrow_mut();
            let main_h = match main_hwnd() {
                Some(h) => h,
                None => {
                    add_log(&mut a, &ui_t, "main", "TEST FAIL: main window HWND unknown", LogType::Error);
                    do_quit(&mut a, &ui_t);
                    return;
                }
            };
            let expected = [
                TITLE_SETTINGS,
                TITLE_UPDATES,
                TITLE_ABOUT,
                TITLE_FILES,
                TITLE_DEPS,
            ];
            let mut ok = 0usize;
            let mut rects: Vec<(&'static str, RECT)> = Vec::new();
            unsafe {
                for want in expected {
                    let mut hwnd: Option<HWND> = None;
                    for h in self_windows() {
                        if h == main_h {
                            continue;
                        }
                        let mut tb = [0u16; 128];
                        let tl = GetWindowTextW(HWND(h as *mut core::ffi::c_void), &mut tb) as usize;
                        if String::from_utf16_lossy(&tb[..tl.min(128)]) == want {
                            hwnd = Some(HWND(h as *mut core::ffi::c_void));
                            break;
                        }
                    }
                    let Some(hwnd) = hwnd else {
                        add_log(
                            &mut a,
                            &ui_t,
                            "main",
                            &format!("TEST FAIL: dialog \"{want}\" not found"),
                            LogType::Error,
                        );
                        continue;
                    };
                    let owned = GetWindow(hwnd, GW_OWNER)
                        .map(|o| o.0 as isize == main_h)
                        .unwrap_or(false);
                    let hooked = GetWindowLongPtrW(hwnd, GWLP_WNDPROC) as usize
                        == pin_pos_proc as *const () as usize;
                    let mut r0 = RECT::default();
                    let mut r1 = RECT::default();
                    let _ = GetWindowRect(hwnd, &mut r0);
                    let _ = SetWindowPos(
                        hwnd,
                        None,
                        r0.left + 150,
                        r0.top + 150,
                        0,
                        0,
                        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
                    );
                    let _ = GetWindowRect(hwnd, &mut r1);
                    let pinned = hooked && r0.left == r1.left && r0.top == r1.top;
                    rects.push((want, r0));
                    if owned && pinned {
                        ok += 1;
                    } else {
                        add_log(
                            &mut a,
                            &ui_t,
                            "main",
                            &format!(
                                "dialog \"{want}\": owned={owned} hooked={hooked} pinned={pinned}"
                            ),
                            LogType::Error,
                        );
                    }
                }
            }
            if ok == expected.len() {
                add_log(
                    &mut a,
                    &ui_t,
                    "main",
                    &format!("TEST PASS: {}/{} sub-windows anchored (no taskbar, immovable)", ok, expected.len()),
                    LogType::Info,
                );
            } else {
                add_log(
                    &mut a,
                    &ui_t,
                    "main",
                    &format!("TEST FAIL: {ok}/{} sub-windows anchored", expected.len()),
                    LogType::Error,
                );
            }
            // Centering check: every window's rect center must sit within
            // 24 px of the primary work-area center.
            let (aw, ah, ox, oy) = work_area();
            let acx = ox + aw / 2.0;
            let acy = oy + ah / 2.0;
            let mut rmain = RECT::default();
            unsafe {
                let _ = GetWindowRect(HWND(main_h as *mut core::ffi::c_void), &mut rmain);
            }
            let mut bad = 0usize;
            let centered: Vec<(&str, RECT)> =
                std::iter::once((TITLE_MAIN, rmain)).chain(rects.iter().map(|(w, r)| (*w, *r))).collect();
            for (label, r) in centered {
                let cx = f64::from(r.left + r.right) / 2.0;
                let cy = f64::from(r.top + r.bottom) / 2.0;
                if (cx - acx).abs() > 24.0 || (cy - acy).abs() > 24.0 {
                    bad += 1;
                    add_log(
                        &mut a,
                        &ui_t,
                        "main",
                        &format!(
                            "\"{label}\" not centered: center=({cx:.0},{cy:.0}) want=({acx:.0},{acy:.0})"
                        ),
                        LogType::Error,
                    );
                }
            }
            if bad == 0 {
                add_log(
                    &mut a,
                    &ui_t,
                    "main",
                    "TEST PASS: all 5 windows centered on work area",
                    LogType::Info,
                );
            } else {
                add_log(
                    &mut a,
                    &ui_t,
                    "main",
                    &format!("TEST FAIL: {bad} window(s) not centered"),
                    LogType::Error,
                );
            }
            do_quit(&mut a, &ui_t);
        },
            );
    }

    slint::run_event_loop()?;
    Ok(())
}
