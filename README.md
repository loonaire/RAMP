# RAMP

*English · [Français](README-fr.md)*

A portable control panel for a local web server on Windows: **Apache, MariaDB, PHP and phpMyAdmin**, written in Rust with [Slint](https://slint.dev).

Drop a single `ramp.exe` into an empty folder. On first launch it downloads the versions you pick, verifies them and installs them next to itself. From then on it starts and stops the servers, opens their configuration and log files, and keeps them up to date.

> NOTE: I have only test what i need, if you find a bug use the issues.

## AI

The base of this tool has been write with Qwen 3.8 Flash Next, after that i have use Claude for the correction of bug and rewrite some parts.
This is fully develop by AI, i don't have touch to code.

## Why this project

This project has been motivated by multiple things:
- XAMPP is not updated since 2022 and the php version in the last version is old
- In XAMPP update the components is complicated because of multiples modifications
- XAMPP is partially open source
- XAMPP don't have a CLI Mode
- With the AI, a tool like XAMPP can be very usefull: the model can use Apache, php and mysql without need to access to real server. With RAMP the AI can do anything on the mariadb server without risk to change something critical.

> Note about the multiplatform: I like create tool multiplatform, i use mainly windows but i also use a linux. XAMPP is available for linux but for now RAMP is only available on windows. Maybe available on linux one day if i need this.


## Highlights

- **Portable**: everything is installed in `ramp.exe`'s folder. The folder can be moved or renamed; paths are fixed up on the next launch.
- **No Windows services**: the servers are plain processes started and stopped by the panel. No administrator rights needed.
- **Pick your versions at install time**: MariaDB LTS lines (end-of-life ones left out), the PHP branches php.net still maintains (active support or security fixes only), Apache Lounge 2.4 builds, the latest phpMyAdmin.
- **Full PHP out of the box**: every extension shipped with PHP is tried at install time, and all those that load on their own are enabled (OPcache included).
- **Safe updates**: archives only, never installers. The SHA256 is always checked, the old version is backed up, the new one must start, and everything is put back otherwise. A *Restore* button returns to the previous version.
- **Careful defaults**: MariaDB listens on `127.0.0.1` only and phpMyAdmin is reachable from the local machine only. Version feeds and checksums travel over HTTPS only, so an archive served by a mirror is accepted only if its SHA256 matches. The `php-cgi` alias is removed (CVE-2024-4577).
- **Lightweight**: software rendering, no OpenGL, so it works in virtual machines and over Remote Desktop.

## Installation

### Requirements

- Windows 10 or 11, 64-bit.
- The **Microsoft Visual C++ 2015-2022 (x64)** runtime, needed by the Windows builds of Apache and PHP. If it is missing, RAMP detects it and offers Microsoft's download link.
- Internet access on first launch and for updates, to `www.apachelounge.com`, `downloads.mariadb.org`, `windows.php.net`, `www.php.net`, `files.phpmyadmin.net` and `api.github.com`. If a firewall blocks them, the install window shows *Retry*.

### First launch

1. Download `RAMP-<version>-win64.zip` from the [Releases](https://github.com/loonaire/RAMP/releases) page. You can compare its hash with the `.sha256` file published next to it:
   ```powershell
   Get-FileHash .\RAMP-0.5.0-win64.zip -Algorithm SHA256
   ```
2. Extract `ramp.exe` into a dedicated, writable folder such as `C:\RAMP`. Avoid `Program Files`, where writing requires administrator rights.
3. Run `ramp.exe`. The *Install RAMP* window lists the available versions, newest preselected. Click *Install*: about 150 MB are downloaded, which takes one to a few minutes depending on the connection. *Later* postpones the installation to the next launch.

## Usage

The main window shows one row per server (Apache, MySQL/MariaDB) with its PIDs, ports and status:

| Button | Action |
|---|---|
| **Start / Stop** | Starts or stops the server. |
| **Admin** | Opens `http://localhost/` (Apache) or phpMyAdmin (MariaDB) in the browser. |
| **Config** | Lists the configuration files (`httpd.conf`, `php.ini`, `my.ini`, `config.inc.php`…) and opens them in the editor. |
| **Logs** | Lists the log files and opens them in the editor. |

The menus open Explorer on the installation folder, the settings (ports, editor, browser), the updates window and the *About* window, which shows the version and the build type. Quitting the panel stops the servers it started.

### Default addresses

| Service | Address |
|---|---|
| Website (`htdocs\`) | http://localhost/ and https://localhost/ (self-signed certificate) |
| phpMyAdmin | http://localhost/phpmyadmin |
| MariaDB | `127.0.0.1:3306`, user `root` **with no password** |

> **Security.** RAMP is meant for local development. Set a password for `root` right after installing. Apache listens on all network interfaces: the Windows firewall decides whether the site is reachable from the local network.

Ports are changed in *File > Settings*. RAMP writes them straight into the servers' configuration files; restart a running server to apply them.

### Installation folder

```
C:\RAMP\
├── ramp.exe
├── ramp.ini        panel settings
├── ramp.log        log (appended on every exit)
├── apache\         Apache httpd (Apache Lounge)
├── mysql\          MariaDB, data in mysql\data\
├── php\            PHP, php.ini
├── phpMyAdmin\
├── htdocs\         website root
├── cgi-bin\
├── tmp\            temporary files, recreated when the servers start
└── .backup\        versions replaced by updates
```

## Updates

The *Updates* menu shows whether updates are pending and opens the *Component Updates* window. For each component it shows the installed version, the target version, the archive size and the branch's support status.

An update always goes through the same steps:
1. download the official archive and check its SHA256;
2. extract it and check that it really holds the announced version;
3. back up the old version in `.backup\`, with its configuration files. For MariaDB the data folder is copied too, up to `DataBackupLimitMB`;
4. swap, then start the new server;
5. automatic return to the old version if any step fails.

The *Offer other release lines* box also offers higher branches (PHP 8.4 to 8.5, MariaDB 11.8 to 12.3…), on top of fixes for the installed branch.

## Settings (`ramp.ini`)

The file is created next to `ramp.exe`; most keys can be changed from *File > Settings*.

| Section | Key | Default | Purpose |
|---|---|---|---|
| `ServicePorts` | `Apache`, `ApacheSSL`, `MySQL` | `80`, `443`, `3306` | Server ports. The ports actually set in `httpd.conf` and `my.ini` take precedence. |
| `Checks` | `CheckDefaultPorts` | `1` | Before starting a server, check that its ports are free. |
| `Common` | `Editor` | `notepad.exe` | Editor for configuration and log files. |
| `Common` | `Browser` | *(empty)* | Browser; empty = default browser. |
| `Common` | `Debug` | `0` | Debug messages in the log. |
| `Updates` | `AllowMajor` | `1` | Offer higher branches. |
| `Updates` | `TargetLine` | *(empty)* | Pin MariaDB to one branch (`11.8`, for example). |
| `Updates` | `KeepBackups` | `2` | Number of backups kept in `.backup\` (the most recent ones, all components together). |
| `Updates` | `DataBackupLimitMB` | `2048` | Maximum size of the MariaDB data folder copied before an update. |

## Command line

`ramp.exe` is a GUI application with no console: these commands open the panel, write their result to the log window and to `ramp.log`, then close it.

```text
ramp --first-run [--no-verify] [--apache <version>] [--mariadb <branch|version>] [--php <branch|version>]
ramp --update-check [--json]
ramp --update-apply <apache|mysql|php|pma> [branch|version]
ramp --update-restore <apache|mysql|php|pma> [backup_folder]
```

Example: `ramp --first-run --php 8.4 --mariadb 11.8` installs without the version window, using the latest releases of those branches.

## Building from source

RAMP builds with the [MSYS2](https://www.msys2.org) GNU toolchain, **UCRT64** environment. `windres` embeds the icon in the executable.

```bash
pacman -S mingw-w64-ucrt-x86_64-rust mingw-w64-ucrt-x86_64-binutils
cargo build --release
cargo test
```

Do not install from cargo's build folder: a `cargo clean` would wipe the servers and the databases. RAMP refuses to install there anyway. For development, point it at another folder with `RAMP_BASEDIR`:

```powershell
$env:RAMP_BASEDIR = "C:\ramp-dev"; cargo run
```

`release.ps1` builds and produces the `dist\RAMP-<version>-win64.zip` package and its `.sha256`. With `-InstallDir`, it also copies `ramp.exe` into an installation folder, leaving the existing installation as it is:

```powershell
.\release.ps1                      # package only
.\release.ps1 -InstallDir C:\RAMP  # package + install or update ramp.exe
```

## Releasing a version

Every `v*` tag pushed to GitHub triggers the [`release.yml`](.github/workflows/release.yml) workflow. It builds on Windows with the same MSYS2 UCRT64 toolchain, runs `release.ps1` and publishes the zip and its SHA256 in a GitHub release. The annotated tag's message becomes the release notes.

1. Update the version in `Cargo.toml` (for example `0.6.0`) and commit.
2. Create an annotated tag matching that version (`v0.6` or `v0.6.0`) and push it on its own:
   ```bash
   git tag -a v0.6 -m "RAMP v0.6: ..."
   git push origin v0.6
   ```

The workflow stops if the tag does not match the version in `Cargo.toml`. A tag with a dash (`v0.6.0-rc1`) creates a pre-release.

## Code layout

| File | Role |
|---|---|
| `src/main.rs` | UI, server management, windows, command line |
| `src/install.rs` | First-run installation, configuration generation |
| `src/update.rs` | Version feeds (Apache Lounge, MariaDB, php.net, phpMyAdmin), update checks and swaps |
| `src/http.rs` | Minimal HTTPS client on WinHTTP (system TLS, system proxy) |
| `src/ports.rs`, `src/netstat.rs` | Configured ports and the processes holding them |
| `src/procs.rs`, `src/pe.rs` | Server processes, missing DLL detection |
| `src/config.rs` | Reading and writing `ramp.ini` |
| `ui/main.slint` | All windows |
| `templates/` | Configuration templates (`httpd.conf`, `php.ini`, `my.ini`, `config.inc.php`, start page) |
| `build.rs` | Slint UI compilation and icon embedding |

## License

RAMP is distributed under the [GPL-3.0](LICENSE) license. Slint is used under its GPLv3 license. Apache, MariaDB, PHP and phpMyAdmin are downloaded from their official sources and remain under their own licenses.
