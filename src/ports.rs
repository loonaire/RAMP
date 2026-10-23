//! The servers take their ports from their own configuration files, never from
//! ramp.ini: httpd.conf (Listen, ServerName, plus the virtual hosts in
//! httpd-vhosts.conf), httpd-ssl.conf (Listen, the _default_ virtual host,
//! ServerName), my.ini (`port` of [client] and [mysqld]), phpMyAdmin's
//! config.inc.php and php.ini (mysqli.default_port). The Settings window writes
//! a new port through to all of them, and every launch reads them back into
//! ramp.ini, so a hand edit of httpd.conf is never contradicted by the panel.

use std::fs;
use std::ops::Range;
use std::path::Path;

pub const HTTPD: &str = "apache\\conf\\httpd.conf";
const VHOSTS: &str = "apache\\conf\\extra\\httpd-vhosts.conf";
pub const SSL: &str = "apache\\conf\\extra\\httpd-ssl.conf";
pub const MYINI: &str = "mysql\\bin\\my.ini";
const PMA: &str = "phpMyAdmin\\config.inc.php";
const PHPINI: &str = "php\\php.ini";

/// What the configuration files say; None where a file or directive is missing.
pub struct Ports {
    pub http: Option<u16>,
    pub https: Option<u16>,
    pub mysql: Option<u16>,
}

pub fn read(basedir: &Path) -> Ports {
    Ports {
        http: first_listen(&basedir.join(HTTPD)),
        https: first_listen(&basedir.join(SSL)),
        mysql: my_ini_port(&basedir.join(MYINI)),
    }
}

/// Plain-http port: every Listen on the current port, the ServerName and the
/// virtual hosts that named it. Ok(lines changed).
pub fn set_http(basedir: &Path, port: u16) -> Result<usize, String> {
    let conf = basedir.join(HTTPD);
    let cur = first_listen(&conf)
        .ok_or_else(|| format!("no Listen directive in {}", conf.display()))?;
    if cur == port {
        return Ok(0);
    }
    let mut n = edit_lines(&conf, |l| retarget(l, cur, port))?;
    let vhosts = basedir.join(VHOSTS);
    if vhosts.is_file() {
        n += edit_lines(&vhosts, |l| retarget(l, cur, port))?;
    }
    Ok(n)
}

/// https port: Listen, the _default_ virtual host and its ServerName.
pub fn set_https(basedir: &Path, port: u16) -> Result<usize, String> {
    let conf = basedir.join(SSL);
    let cur = first_listen(&conf)
        .ok_or_else(|| format!("no Listen directive in {}", conf.display()))?;
    if cur == port {
        return Ok(0);
    }
    edit_lines(&conf, |l| retarget(l, cur, port))
}

/// MariaDB port, and the two clients that must follow it: phpMyAdmin and
/// PHP's mysqli default (scripts calling mysqli_connect without a port).
pub fn set_mysql(basedir: &Path, port: u16) -> Result<usize, String> {
    let val = port.to_string();
    let mut n = edit_lines(&basedir.join(MYINI), |l| {
        set_value(l, "port", &['#', ';'], &val)
    })?;
    let pma = basedir.join(PMA);
    if pma.is_file() {
        n += set_pma_port(&pma, port)?;
    }
    let php = basedir.join(PHPINI);
    if php.is_file() {
        n += edit_lines(&php, |l| set_value(l, "mysqli.default_port", &[';'], &val))?;
    }
    Ok(n)
}

// ------------------------------------------------------------------ helpers

/// The line without its indentation, unless it is blank or an Apache comment.
fn active(line: &str) -> Option<&str> {
    let t = line.trim_start();
    (!t.is_empty() && !t.starts_with('#')).then_some(t)
}

/// Port of a Listen argument: `80`, `0.0.0.0:80`, `[::]:80`.
fn listen_port(arg: &str) -> Option<u16> {
    arg.rsplit(':').next()?.parse().ok()
}

fn first_listen(path: &Path) -> Option<u16> {
    let txt = fs::read_to_string(path).ok()?;
    txt.lines()
        .filter_map(active)
        .filter_map(|t| {
            let mut it = t.split_whitespace();
            it.next()
                .filter(|w| w.eq_ignore_ascii_case("Listen"))
                .and_then(|_| it.next())
        })
        .find_map(listen_port)
}

/// Move the port `old` of a Listen, ServerName or <VirtualHost> line to `new`,
/// keeping addresses, host names, quotes and spacing as they are.
fn retarget(line: &str, old: u16, new: u16) -> Option<String> {
    let t = active(line)?;
    let word = t.split_whitespace().next()?;
    let lw = word.to_ascii_lowercase();
    if lw != "listen" && lw != "servername" && lw != "<virtualhost" {
        return None;
    }
    let indent = &line[..line.len() - t.len()];
    let args = map_tokens(&t[word.len()..], |tok| {
        let (core, close) = match tok.strip_suffix('>') {
            Some(c) => (c, ">"),
            None => (tok, ""),
        };
        let q = if core.starts_with('"') { "\"" } else { "" };
        let bare = core.trim_matches('"');
        match bare.rsplit_once(':') {
            Some((host, p)) if p.parse() == Ok(old) => format!("{q}{host}:{new}{q}{close}"),
            None if lw == "listen" && bare.parse() == Ok(old) => format!("{q}{new}{q}{close}"),
            _ => tok.to_string(),
        }
    });
    Some(format!("{indent}{word}{args}"))
}

/// Apply `f` to every whitespace-separated token of `s`, whitespace kept.
fn map_tokens(s: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    let mut tok = String::new();
    for c in s.chars() {
        if c.is_whitespace() {
            if !tok.is_empty() {
                out.push_str(&f(&tok));
                tok.clear();
            }
            out.push(c);
        } else {
            tok.push(c);
        }
    }
    if !tok.is_empty() {
        out.push_str(&f(&tok));
    }
    out
}

/// `key = value` line of an ini file: the key, and where the trimmed value sits.
fn key_value<'a>(line: &'a str, comments: &[char]) -> Option<(&'a str, Range<usize>)> {
    let t = line.trim_start();
    if t.is_empty() || t.starts_with(comments) || t.starts_with('[') {
        return None;
    }
    let eq = line.find('=')?;
    let rest = &line[eq + 1..];
    let start = eq + 1 + (rest.len() - rest.trim_start().len());
    Some((line[..eq].trim(), start..start + rest.trim().len()))
}

fn set_value(line: &str, key: &str, comments: &[char], val: &str) -> Option<String> {
    let (k, r) = key_value(line, comments)?;
    k.eq_ignore_ascii_case(key)
        .then(|| format!("{}{val}{}", &line[..r.start], &line[r.end..]))
}

/// The [mysqld] port of my.ini, else the first port the file names.
fn my_ini_port(path: &Path) -> Option<u16> {
    let txt = fs::read_to_string(path).ok()?;
    let mut section = String::new();
    let mut first = None;
    for line in txt.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            section = t.trim_matches(['[', ']']).trim().to_ascii_lowercase();
            continue;
        }
        let Some((k, r)) = key_value(line, &['#', ';']) else {
            continue;
        };
        if !k.eq_ignore_ascii_case("port") {
            continue;
        }
        let v = line[r].trim_matches(['"', '\'']).parse().ok();
        if section == "mysqld" && v.is_some() {
            return v;
        }
        first = first.or(v);
    }
    first
}

/// `$cfg['Servers'][$i]['port'] = '3306';`. A config.inc.php without that line
/// relies on phpMyAdmin's 3306 default: one is added under the host line.
fn set_pma_port(path: &Path, port: u16) -> Result<usize, String> {
    let live = |l: &str| {
        let t = l.trim_start();
        !(t.starts_with("//") || t.starts_with('#') || t.starts_with('*') || t.starts_with("/*"))
    };
    let is_port = |l: &str| live(l) && l.contains("['port']") && l.contains('=');
    let txt = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if txt.lines().any(is_port) {
        return edit_lines(path, |l| {
            if !is_port(l) {
                return None;
            }
            let eq = l.find('=')?;
            let semi = l.rfind(';').filter(|s| *s > eq)?;
            Some(format!("{} '{port}'{}", &l[..eq + 1], &l[semi..]))
        });
    }
    if port == 3306 {
        return Ok(0);
    }
    let nl = if txt.contains("\r\n") { "\r\n" } else { "\n" };
    let mut added = false;
    let n = edit_lines(path, |l| {
        if added || !live(l) || !l.contains("['host']") {
            return None;
        }
        added = true;
        let indent = &l[..l.len() - l.trim_start().len()];
        Some(format!("{l}{nl}{indent}$cfg['Servers'][$i]['port'] = '{port}';"))
    })?;
    if n == 0 {
        return Err(format!("no ['host'] line in {} to set the port next to", path.display()));
    }
    Ok(n)
}

/// Rewrite a text file line by line; written back only when something changed.
/// A CRLF file stays CRLF. Ok(number of lines changed).
fn edit_lines(path: &Path, mut edit: impl FnMut(&str) -> Option<String>) -> Result<usize, String> {
    let txt = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let nl = if txt.contains("\r\n") { "\r\n" } else { "\n" };
    let mut n = 0usize;
    let mut out = String::with_capacity(txt.len() + 16);
    for line in txt.lines() {
        match edit(line) {
            Some(new) if new != line => {
                out.push_str(&new);
                n += 1;
            }
            _ => out.push_str(line),
        }
        out.push_str(nl);
    }
    if n > 0 {
        fs::write(path, out).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retarget_moves_only_the_old_port() {
        assert_eq!(retarget("Listen 80", 80, 8080).as_deref(), Some("Listen 8080"));
        assert_eq!(
            retarget("  Listen 0.0.0.0:80", 80, 8080).as_deref(),
            Some("  Listen 0.0.0.0:8080")
        );
        assert_eq!(retarget("Listen [::]:80", 80, 81).as_deref(), Some("Listen [::]:81"));
        assert_eq!(
            retarget("ServerName localhost:80", 80, 8080).as_deref(),
            Some("ServerName localhost:8080")
        );
        assert_eq!(
            retarget("<VirtualHost _default_:443>", 443, 8443).as_deref(),
            Some("<VirtualHost _default_:8443>")
        );
        assert_eq!(
            retarget("<VirtualHost *:80 *:8000>", 80, 81).as_deref(),
            Some("<VirtualHost *:81 *:8000>")
        );
        // Unchanged: other ports, comments, other directives.
        assert_eq!(retarget("Listen 8000", 80, 81).as_deref(), Some("Listen 8000"));
        assert_eq!(retarget("#Listen 80", 80, 81), None);
        assert_eq!(retarget("Define SRVROOT \"c:/x:80\"", 80, 81), None);
    }

    #[test]
    fn set_value_keeps_layout() {
        assert_eq!(
            set_value("port            = 3306 ", "port", &['#', ';'], "3307").as_deref(),
            Some("port            = 3307 ")
        );
        assert_eq!(set_value("port= 3306", "port", &['#'], "3307").as_deref(), Some("port= 3307"));
        assert_eq!(set_value("#port = 3306", "port", &['#'], "3307"), None);
        assert_eq!(set_value("report = 1", "port", &['#'], "3307"), None);
    }

    fn tree(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("ramp-ports-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        for d in ["apache\\conf\\extra", "mysql\\bin", "phpMyAdmin", "php"] {
            fs::create_dir_all(base.join(d)).unwrap();
        }
        base
    }

    #[test]
    fn ports_round_trip_through_the_config_files() {
        let base = tree("rt");
        fs::write(base.join(HTTPD), "#Listen 12.34.56.78:80\r\nListen 80\r\nServerName localhost:80\r\n").unwrap();
        fs::write(base.join(VHOSTS), "<VirtualHost *:80>\n</VirtualHost>\n").unwrap();
        fs::write(base.join(SSL), "Listen 443\n<VirtualHost _default_:443>\nServerName localhost:443\n").unwrap();
        fs::write(
            base.join(MYINI),
            "[client]\nport            = 3306 \n[mysqld]\nport= 3306\n[mysqldump]\nquick\n",
        )
        .unwrap();
        fs::write(base.join(PMA), "<?php\n$cfg['Servers'][$i]['host'] = '127.0.0.1';\n$cfg['Servers'][$i]['port'] = '3306';\n").unwrap();
        fs::write(base.join(PHPINI), "[MySQLi]\nmysqli.default_port = 3306\n").unwrap();

        let p = read(&base);
        assert_eq!((p.http, p.https, p.mysql), (Some(80), Some(443), Some(3306)));

        assert_eq!(set_http(&base, 8080).unwrap(), 3);
        assert_eq!(set_https(&base, 8443).unwrap(), 3);
        assert_eq!(set_mysql(&base, 3307).unwrap(), 4);
        let p = read(&base);
        assert_eq!((p.http, p.https, p.mysql), (Some(8080), Some(8443), Some(3307)));

        let httpd = fs::read_to_string(base.join(HTTPD)).unwrap();
        assert_eq!(httpd, "#Listen 12.34.56.78:80\r\nListen 8080\r\nServerName localhost:8080\r\n");
        assert!(fs::read_to_string(base.join(VHOSTS)).unwrap().contains("<VirtualHost *:8080>"));
        assert!(fs::read_to_string(base.join(PMA)).unwrap().contains("['port'] = '3307';"));
        assert!(fs::read_to_string(base.join(PHPINI)).unwrap().contains("mysqli.default_port = 3307"));
        // Same port again: nothing left to change.
        assert_eq!(set_http(&base, 8080).unwrap(), 0);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn pma_config_without_port_gets_a_port_line() {
        let base = tree("pma");
        fs::write(base.join(MYINI), "[mysqld]\nport=3306\n").unwrap();
        fs::write(base.join(PMA), "<?php\n    $cfg['Servers'][$i]['host'] = '127.0.0.1';\n").unwrap();
        set_mysql(&base, 3307).unwrap();
        assert_eq!(
            fs::read_to_string(base.join(PMA)).unwrap(),
            "<?php\n    $cfg['Servers'][$i]['host'] = '127.0.0.1';\n    $cfg['Servers'][$i]['port'] = '3307';\n"
        );
        let _ = fs::remove_dir_all(&base);
    }
}
