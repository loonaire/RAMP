use std::path::Path;
use image::ImageEncoder;

/// Sizes embedded in the application .ico, from the single assets/logo.png.
const ICON_SIZES: [u32; 7] = [16, 24, 32, 48, 64, 128, 256];

fn ico_entry_dims(size: u32) -> (u8, u8) {
    // The ICO directory encodes 256 as a 0 byte.
    let d = if size >= 256 { 0 } else { size as u8 };
    (d, d)
}

/// PNG-in-ICO (Vista+): one directory entry + one PNG frame per size.
fn build_ico(png_frames: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0]); // reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // type: icon
    out.extend_from_slice(&(png_frames.len() as u16).to_le_bytes());
    let dir_len = 6 + 16 * png_frames.len();
    let mut offset = dir_len;
    for (size, png) in png_frames {
        let (w, h) = ico_entry_dims(*size);
        out.push(w);
        out.push(h);
        out.push(0); // color count
        out.push(0); // reserved
        out.extend_from_slice(&1u16.to_le_bytes()); // planes
        out.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
        out.extend_from_slice(&(png.len() as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += png.len();
    }
    for (_, png) in png_frames {
        out.extend_from_slice(png);
    }
    out
}

fn generate_ico(out_dir: &Path) -> Option<std::path::PathBuf> {
    let src = image::open("assets/logo.png").ok()?.into_rgba8();
    let mut frames = Vec::new();
    for size in ICON_SIZES {
        let small = image::imageops::resize(&src, size, size, image::imageops::FilterType::Lanczos3);
        let mut png = Vec::new();
        {
            let enc = image::codecs::png::PngEncoder::new(&mut png);
            enc.write_image(small.as_raw(), size, size, image::ExtendedColorType::Rgba8)
                .ok()?;
        }
        frames.push((size, png));
    }
    let ico = out_dir.join("ramp.ico");
    std::fs::write(&ico, build_ico(&frames)).ok()?;
    Some(ico)
}

/// Compile the .ico into a .res with windres and link it into the exe, so every
/// `cargo build` carries the logo (Explorer/taskbar/Alt-Tab file icon).
fn embed_icon(out_dir: &Path) {
    let ico = match generate_ico(out_dir) {
        Some(p) => p,
        None => {
            println!("cargo:warning=assets/logo.png not found; building without icon");
            return;
        }
    };
    let rc = out_dir.join("ramp.rc");
    // Forward slashes: accepted by windres, no escaping needed.
    let ico_pos = ico.display().to_string().replace('\\', "/");
    std::fs::write(&rc, format!("1 ICON \"{ico_pos}\"\n")).unwrap();
    let res = out_dir.join("ramp.res");
    let windres = std::env::var("WINDRES").unwrap_or_else(|_| "windres".into());
    // -O coff: a real COFF object ld can link (plain -O res is NOT linkable).
    let ok = match std::process::Command::new(&windres)
        .arg("-J")
        .arg("rc")
        .arg("-O")
        .arg("coff")
        .arg("-i")
        .arg(&rc)
        .arg("-o")
        .arg(&res)
        .status()
    {
        Ok(s) => s.success(),
        Err(_) => false,
    };
    if ok && res.exists() {
        // GNU ld takes the .res straight as a linker input.
        println!("cargo:rustc-link-arg={}", res.display());
    } else {
        println!("cargo:warning=windres not found: built without exe icon");
    }
}

fn main() {
    println!("cargo:rerun-if-changed=assets/logo.png");
    println!("cargo:rerun-if-changed=ui/main.slint");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    embed_icon(&out_dir);
    slint_build::compile_with_config(
        "ui/main.slint",
        slint_build::CompilerConfiguration::new().with_style("fluent-dark".into()),
    )
    .unwrap();
}
