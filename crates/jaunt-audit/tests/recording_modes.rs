use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use jaunt_audit::{
    DirectoryLimits, DirectorySink, FILE_MODE, ROOT_MODE, RecordingKey, RecordingSink,
};
use jaunt_record::{MANIFEST_VERSION, SessionKind, SessionManifest};
use rustix::fs::Mode;
use rustix::process::umask;

const ID: &str = "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11";

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn manifest() -> SessionManifest {
    SessionManifest {
        version: MANIFEST_VERSION,
        session_id: ID.to_owned(),
        kind: SessionKind::Shell,
        node: "node-1".to_owned(),
        user: "user-1".to_owned(),
        login: "deploy".to_owned(),
        started_at: 1,
        ended_at: Some(2),
        exit_status: Some(0),
        command: None,
        bytes_out: 1,
        bytes_in: 0,
        input_recorded: false,
        chunks: 1,
        raw_bytes: 4,
        incomplete: false,
        dropped_chunks: 0,
        digest: None,
    }
}

#[test]
fn directories_and_files_get_their_modes_whatever_the_umask() {
    for mask in [0o022, 0o077] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("recordings");
        let previous = umask(Mode::from_raw_mode(mask));
        let sink = DirectorySink::create(
            &root,
            DirectoryLimits {
                min_free_bytes: 0,
                max_total_raw: 1024,
            },
        )
        .unwrap();
        let key = RecordingKey::new(ID, 0).unwrap();
        let mut staged = sink.begin(&key).unwrap();
        staged.write(0, b"data").unwrap();
        staged.commit(&manifest()).unwrap();
        umask(previous);

        let month = root.join("1970").join("01");
        for path in [root.clone(), root.join("1970"), month.clone()] {
            assert_eq!(mode_of(&path), ROOT_MODE, "{mask:o} {}", path.display());
        }
        for name in [format!("{ID}.cast"), format!("{ID}.manifest.json")] {
            assert_eq!(mode_of(&month.join(&name)), FILE_MODE, "{mask:o} {name}");
        }
    }
}
