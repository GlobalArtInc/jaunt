use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::{Fingerprint, HashAlg, PublicKey};
use zeroize::Zeroizing;

use crate::error::CaError;

#[cfg(unix)]
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

pub(crate) const SHA256_HEX_LEN: usize = 64;

pub(crate) fn fingerprint_hex(key: &PublicKey) -> String {
    to_hex(key.fingerprint(HashAlg::Sha256).as_bytes())
}

pub(crate) fn fingerprint_from_hex(hex: &str) -> Option<Fingerprint> {
    if hex.len() != SHA256_HEX_LEN {
        return None;
    }
    let mut digest = [0u8; 32];
    let mut nibbles = hex.bytes().map(nibble);
    for byte in digest.iter_mut() {
        let high = nibbles.next()??;
        let low = nibbles.next()??;
        *byte = (high << 4) | low;
    }
    Some(Fingerprint::Sha256(digest))
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

pub(crate) fn ensure_private_dir(path: &Path, tighten_existing: bool) -> io::Result<()> {
    let existed = match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => true,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "path exists and is not a directory",
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => false,
        Err(err) => return Err(err),
    };
    if existed && !tighten_existing {
        return Ok(());
    }
    if !existed {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(DIR_MODE);
        builder.create(path)?;
    }
    #[cfg(unix)]
    fs::set_permissions(path, Permissions::from_mode(DIR_MODE))?;
    Ok(())
}

pub(crate) fn random_hex(len: usize) -> io::Result<String> {
    let mut bytes = vec![0u8; len];
    OsRng.try_fill_bytes(&mut bytes).map_err(io::Error::other)?;
    Ok(to_hex(&bytes))
}

pub(crate) fn create_new_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    builder.mode(DIR_MODE);
    builder.create(path)?;
    #[cfg(unix)]
    fs::set_permissions(path, Permissions::from_mode(DIR_MODE))?;
    Ok(())
}

pub(crate) fn read_limited(path: &Path, max: u64) -> Result<Zeroizing<Vec<u8>>, CaError> {
    let capacity = usize::try_from(max.saturating_add(1)).map_err(|_| CaError::CorruptStore {
        path: path.to_path_buf(),
        reason: "read limit is too large",
    })?;
    let file = File::open(path).map_err(CaError::io("open", path))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(CaError::io("read", path))?;
    if buf.len() > capacity - 1 {
        return Err(CaError::CorruptStore {
            path: path.to_path_buf(),
            reason: "file is larger than expected",
        });
    }
    Ok(buf)
}

pub(crate) fn exists(path: &Path) -> Result<bool, CaError> {
    path.try_exists().map_err(CaError::io("stat", path))
}

pub(crate) fn write_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    write_new_with(path, contents, &|_| Ok(()))
}

pub(crate) fn write_new_with(
    path: &Path,
    contents: &[u8],
    after_link: &dyn Fn(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;

    let temp: PathBuf = dir.join(format!(".{name}.{}.tmp", random_hex(8)?));

    let linked = write_temp(&temp, contents).and_then(|()| link_new(&temp, path));
    let removed = fs::remove_file(&temp);
    linked?;
    let finished = removed
        .and_then(|()| after_link(path))
        .and_then(|()| sync_dir(dir));
    if let Err(err) = finished {
        drop(fs::remove_file(path));
        return Err(err);
    }
    Ok(())
}

fn link_new(temp: &Path, path: &Path) -> io::Result<()> {
    fs::hard_link(temp, path).map_err(|err| {
        if err.kind() == io::ErrorKind::AlreadyExists {
            err
        } else {
            io::Error::new(
                err.kind(),
                format!("{err}; the filesystem must support hard links"),
            )
        }
    })
}

fn write_temp(temp: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(FILE_MODE);
    let mut file = options.open(temp)?;
    #[cfg(unix)]
    file.set_permissions(Permissions::from_mode(FILE_MODE))?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use ssh_key::{Algorithm, PrivateKey};

    use super::{fingerprint_from_hex, fingerprint_hex, read_limited, write_new};
    use crate::error::CaError;

    #[test]
    fn read_limited_refuses_files_over_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"123456789").unwrap();
        assert_eq!(&**read_limited(&path, 9).unwrap(), b"123456789");
        assert_eq!(&**read_limited(&path, 10).unwrap(), b"123456789");
        assert!(matches!(
            read_limited(&path, 8),
            Err(CaError::CorruptStore { .. })
        ));
        assert!(matches!(
            read_limited(&path, 0),
            Err(CaError::CorruptStore { .. })
        ));
    }

    #[test]
    fn hex_round_trips_and_rejects_malformed_input() {
        let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        let hex = fingerprint_hex(key.public_key());
        assert_eq!(hex.len(), 64);
        assert_eq!(
            fingerprint_from_hex(&hex),
            Some(key.public_key().fingerprint(ssh_key::HashAlg::Sha256))
        );
        assert!(fingerprint_from_hex(&hex.to_uppercase()).is_none());
        assert!(fingerprint_from_hex(&hex[1..]).is_none());
        assert!(fingerprint_from_hex(&format!("{hex}0")).is_none());
        assert!(fingerprint_from_hex(&format!("../{}", &hex[3..])).is_none());
    }

    #[test]
    fn write_new_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        write_new(&path, b"first").unwrap();
        let err = write_new(&path, b"second").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
