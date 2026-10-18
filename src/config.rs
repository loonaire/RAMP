use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

pub type Ini = BTreeMap<String, Vec<(String, String)>>;

pub fn parse_ini(text: &str) -> Ini {
    let mut ini: Ini = BTreeMap::new();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_string();
        } else if let Some(eq) = line.find('=') {
            let k = line[..eq].trim().to_string();
            let v = line[eq + 1..].trim().to_string();
            ini.entry(section.clone()).or_default().push((k, v));
        }
    }
    ini
}

pub fn get_str(ini: &Ini, section: &str, key: &str, default: &str) -> String {
    ini.get(section)
        .and_then(|kv| kv.iter().find(|(k, _)| k == key))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| default.to_string())
}

pub fn get_bool(ini: &Ini, section: &str, key: &str, default: bool) -> bool {
    match ini
        .get(section)
        .and_then(|kv| kv.iter().find(|(k, _)| k == key))
    {
        Some((_, v)) => v.trim() != "0",
        None => default,
    }
}

pub fn get_u16(ini: &Ini, section: &str, key: &str, default: u16) -> u16 {
    get_str(ini, section, key, "").parse().unwrap_or(default)
}

pub fn get_i32(ini: &Ini, section: &str, key: &str, default: i32) -> i32 {
    get_str(ini, section, key, "").parse().unwrap_or(default)
}

pub fn save_ini(path: &Path, ini: &Ini) -> io::Result<()> {
    let mut out = String::new();
    for (section, kv) in ini {
        out.push_str(&format!("[{}]\n", section));
        for (k, v) in kv {
            out.push_str(&format!("{}={}\n", k, v));
        }
        out.push('\n');
    }
    fs::write(path, out)
}

#[derive(Clone)]
pub struct Config {
    pub editor: String,
    pub browser: String,
    pub show_debug: bool,
    pub check_ports: bool,
    pub apache_port: u16,
    pub apache_ssl_port: u16,
    pub mysql_port: u16,
    pub apache_binary: String,
    pub mysql_binary: String,
    pub win_left: i32,
    pub win_top: i32,
    pub win_width: i32,
    pub win_height: i32,
    pub upd_allow_major: bool,
    pub upd_keep_backups: i32,
    pub upd_target_line: String,
    pub upd_data_backup_limit_mb: i32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            editor: "notepad.exe".into(),
            browser: String::new(),
            show_debug: false,
            check_ports: true,
            apache_port: 80,
            apache_ssl_port: 443,
            mysql_port: 3306,
            apache_binary: "httpd.exe".into(),
            mysql_binary: "mysqld.exe".into(),
            win_left: -1,
            win_top: -1,
            win_width: -1,
            win_height: -1,
            upd_allow_major: true,
            upd_keep_backups: 2,
            upd_target_line: String::new(),
            upd_data_backup_limit_mb: 2048,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Config {
        let text = fs::read_to_string(path).unwrap_or_default();
        let ini = parse_ini(&text);
        Config {
            editor: get_str(&ini, "Common", "Editor", "notepad.exe"),
            browser: get_str(&ini, "Common", "Browser", ""),
            show_debug: get_bool(&ini, "Common", "Debug", false),
            check_ports: get_bool(&ini, "Checks", "CheckDefaultPorts", true),
            apache_port: get_u16(&ini, "ServicePorts", "Apache", 80),
            apache_ssl_port: get_u16(&ini, "ServicePorts", "ApacheSSL", 443),
            mysql_port: get_u16(&ini, "ServicePorts", "MySQL", 3306),
            apache_binary: get_str(&ini, "BinaryNames", "Apache", "httpd.exe"),
            mysql_binary: get_str(&ini, "BinaryNames", "MySQL", "mysqld.exe"),
            win_left: get_i32(&ini, "WindowSettings", "Left", -1),
            win_top: get_i32(&ini, "WindowSettings", "Top", -1),
            win_width: get_i32(&ini, "WindowSettings", "Width", -1),
            win_height: get_i32(&ini, "WindowSettings", "Height", -1),
            upd_allow_major: get_bool(&ini, "Updates", "AllowMajor", true),
            upd_keep_backups: get_i32(&ini, "Updates", "KeepBackups", 2),
            upd_target_line: get_str(&ini, "Updates", "TargetLine", ""),
            upd_data_backup_limit_mb: get_i32(&ini, "Updates", "DataBackupLimitMB", 2048),
        }
    }

    pub fn to_ini(&self) -> Ini {
        let mut ini: Ini = BTreeMap::new();
        ini.insert(
            "Common".into(),
            vec![
                ("Editor".into(), self.editor.clone()),
                ("Browser".into(), self.browser.clone()),
                ("Debug".into(), b_to_ini(self.show_debug)),
            ],
        );
        ini.insert(
            "Checks".into(),
            vec![("CheckDefaultPorts".into(), b_to_ini(self.check_ports))],
        );
        ini.insert(
            "BinaryNames".into(),
            vec![
                ("Apache".into(), self.apache_binary.clone()),
                ("MySQL".into(), self.mysql_binary.clone()),
            ],
        );
        ini.insert(
            "ServicePorts".into(),
            vec![
                ("Apache".into(), self.apache_port.to_string()),
                ("ApacheSSL".into(), self.apache_ssl_port.to_string()),
                ("MySQL".into(), self.mysql_port.to_string()),
            ],
        );
        ini.insert(
            "WindowSettings".into(),
            vec![
                ("Left".into(), self.win_left.to_string()),
                ("Top".into(), self.win_top.to_string()),
                ("Width".into(), self.win_width.to_string()),
                ("Height".into(), self.win_height.to_string()),
            ],
        );
        ini.insert(
            "Updates".into(),
            vec![
                ("AllowMajor".into(), b_to_ini(self.upd_allow_major)),
                ("KeepBackups".into(), self.upd_keep_backups.to_string()),
                ("TargetLine".into(), self.upd_target_line.clone()),
                (
                    "DataBackupLimitMB".into(),
                    self.upd_data_backup_limit_mb.to_string(),
                ),
            ],
        );
        ini
    }

    pub fn save(&self, path: &Path) {
        let _ = save_ini(path, &self.to_ini());
    }
}

fn b_to_ini(b: bool) -> String {
    if b { "1" } else { "0" }.into()
}
