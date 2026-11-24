use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const ENTRY: &str = "index.html";
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("assets");
    let out = PathBuf::from(env::var("OUT_DIR")?).join("assets_table.rs");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets");

    let mut files = Vec::new();
    collect(&root, "", &mut files)?;
    files.sort();
    if !files.iter().any(|relative| relative == ENTRY) {
        return Err(format!("assets/{ENTRY} is missing").into());
    }

    let mut table = String::from("static TABLE: &[Asset] = &[\n");
    for relative in &files {
        let location = root.join(relative);
        let bytes = fs::read(&location)?;
        let content_type = content_type(relative)
            .ok_or_else(|| format!("assets/{relative} has no known content type"))?;
        let location = location
            .to_str()
            .ok_or_else(|| format!("assets/{relative} has a path that is not unicode"))?;
        writeln!(
            table,
            "    Asset {{ path: {relative:?}, content_type: {content_type:?}, \
             bytes: include_bytes!({location:?}), etag: {:?} }},",
            etag(&bytes)
        )?;
    }
    table.push_str("];\n");
    fs::write(out, table)?;
    Ok(())
}

fn collect(directory: &Path, prefix: &str, files: &mut Vec<String>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "an asset has a name that is not unicode")?;
        if name.starts_with('.') {
            continue;
        }
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(
                format!("asset name {name:?} has characters outside [A-Za-z0-9._-]").into(),
            );
        }
        let relative = format!("{prefix}{name}");
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect(&entry.path(), &format!("{relative}/"), files)?;
        } else if kind.is_file() {
            files.push(relative);
        } else {
            return Err(format!("asset {relative:?} is neither a file nor a directory").into());
        }
    }
    Ok(())
}

fn content_type(path: &str) -> Option<&'static str> {
    let extension = path.rsplit_once('.')?.1.to_ascii_lowercase();
    let content_type = match extension.as_str() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        _ => return None,
    };
    Some(content_type)
}

fn etag(bytes: &[u8]) -> String {
    let hash = bytes.iter().fold(FNV_OFFSET, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    });
    format!("\"{hash:016x}-{:x}\"", bytes.len())
}
