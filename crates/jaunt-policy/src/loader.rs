use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle};
use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy};
use sha2::{Digest, Sha256};

use crate::access_test::AccessTest;
use crate::policy::{PolicySet, Role};
use crate::raw::{Compiled, RawDocument};

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FILES: usize = 512;
const MAX_ERRORS: usize = 100;
const MAX_ERRORS_PER_FILE: usize = 100;
const GENERATION_LINK: &str = "..data";

pub(crate) struct SourceFile {
    pub(crate) name: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    pub file: String,
    pub document: Option<usize>,
    pub message: String,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.file.is_empty() {
            return f.write_str(&self.message);
        }
        match self.document {
            Some(document) => write!(f, "{}: document {}: {}", self.file, document, self.message),
            None => write!(f, "{}: {}", self.file, self.message),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadErrors {
    errors: Vec<LoadError>,
    input_hash: Option<String>,
}

impl LoadErrors {
    fn new(errors: Vec<LoadError>) -> Self {
        LoadErrors::with_input_hash(errors, None)
    }

    fn with_input_hash(mut errors: Vec<LoadError>, input_hash: Option<String>) -> Self {
        if errors.len() > MAX_ERRORS {
            let omitted = errors.len() - MAX_ERRORS;
            errors.truncate(MAX_ERRORS);
            errors.push(LoadError {
                file: String::new(),
                document: None,
                message: format!("{omitted} more errors omitted"),
            });
        }
        LoadErrors { errors, input_hash }
    }

    pub fn input_hash(&self) -> Option<&str> {
        self.input_hash.as_deref()
    }

    pub fn errors(&self) -> &[LoadError] {
        &self.errors
    }

    pub fn messages(&self) -> Vec<String> {
        self.errors.iter().map(LoadError::to_string).collect()
    }
}

impl fmt::Display for LoadErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.errors.iter().enumerate() {
            if index > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for LoadErrors {}

fn file_error(file: &str, message: impl Into<String>) -> LoadError {
    LoadError {
        file: file.to_owned(),
        document: None,
        message: message.into(),
    }
}

fn document_error(file: &str, document: usize, message: impl Into<String>) -> LoadError {
    LoadError {
        file: file.to_owned(),
        document: Some(document),
        message: message.into(),
    }
}

fn byte_len(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

pub(crate) fn hash_files(files: &[SourceFile]) -> String {
    let mut ordered: Vec<&SourceFile> = files.iter().collect();
    ordered.sort_by(|a, b| a.name.cmp(&b.name));
    let mut hasher = Sha256::new();
    for file in ordered {
        hasher.update(file.name.as_bytes());
        hasher.update([0u8]);
        hasher.update(&file.bytes);
        hasher.update([0u8]);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_policy_file_name(name: &str) -> bool {
    !name.starts_with('.') && (name.ends_with(".yaml") || name.ends_with(".yml"))
}

fn read_limited(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

struct Candidate {
    name: String,
    path: PathBuf,
    len: u64,
}

fn resolve_generation(root: &Path) -> Result<Option<PathBuf>, String> {
    let link = root.join(GENERATION_LINK);
    match fs::symlink_metadata(&link) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("cannot resolve {GENERATION_LINK}: {err}")),
    }
    let generation = fs::canonicalize(&link)
        .map_err(|err| format!("cannot resolve {GENERATION_LINK}: {err}"))?;
    if !generation.starts_with(root) || !generation.is_dir() {
        return Err(format!(
            "{GENERATION_LINK} must resolve to a directory inside the policy directory"
        ));
    }
    Ok(Some(generation))
}

pub fn load_dir(dir: &Path) -> Result<PolicySet, LoadErrors> {
    let dir_label = dir.display().to_string();
    let root = fs::canonicalize(dir).map_err(|err| {
        LoadErrors::new(vec![file_error(
            &dir_label,
            format!("cannot read policy directory: {err}"),
        )])
    })?;
    let generation = resolve_generation(&root)
        .map_err(|message| LoadErrors::new(vec![file_error(&dir_label, message)]))?;
    let source = generation.unwrap_or(root);
    load_resolved(&source, &dir_label)
}

fn load_resolved(dir: &Path, dir_label: &str) -> Result<PolicySet, LoadErrors> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            return Err(LoadErrors::new(vec![file_error(
                dir_label,
                format!("cannot read policy directory: {err}"),
            )]));
        }
    };

    let mut errors = Vec::new();
    let mut candidates: Vec<Candidate> = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                errors.push(file_error(
                    dir_label,
                    format!("cannot read directory entry: {err}"),
                ));
                continue;
            }
        };
        let raw_name = entry.file_name();
        let lossy_name = raw_name.to_string_lossy();
        if !is_policy_file_name(&lossy_name) {
            continue;
        }
        let Some(name) = raw_name.to_str() else {
            errors.push(file_error(&lossy_name, "file name is not valid UTF-8"));
            continue;
        };
        let len = match fs::metadata(entry.path()) {
            Ok(metadata) if metadata.is_file() => metadata.len(),
            Ok(_) => continue,
            Err(err) => {
                errors.push(file_error(name, format!("cannot stat file: {err}")));
                continue;
            }
        };
        let path = match fs::canonicalize(entry.path()) {
            Ok(path) if path.starts_with(dir) => path,
            Ok(_) => {
                errors.push(file_error(
                    name,
                    "file resolves outside the policy directory",
                ));
                continue;
            }
            Err(err) => {
                errors.push(file_error(name, format!("cannot resolve file: {err}")));
                continue;
            }
        };
        if candidates.len() >= MAX_FILES {
            errors.push(file_error(
                dir_label,
                format!("more than {MAX_FILES} policy files"),
            ));
            return Err(LoadErrors::new(errors));
        }
        candidates.push(Candidate {
            name: name.to_owned(),
            path,
            len,
        });
    }
    candidates.sort_by(|a, b| a.name.cmp(&b.name));

    let mut files = Vec::new();
    let mut total: u64 = 0;
    for candidate in candidates {
        let name = candidate.name;
        if candidate.len > MAX_FILE_BYTES {
            errors.push(file_error(&name, "file is larger than the 1 MiB limit"));
            continue;
        }
        if total.saturating_add(candidate.len) > MAX_TOTAL_BYTES {
            errors.push(file_error(
                &name,
                "policy set exceeds the 8 MiB total limit",
            ));
            break;
        }
        match read_limited(&candidate.path) {
            Ok(bytes) if byte_len(bytes.len()) > MAX_FILE_BYTES => {
                errors.push(file_error(&name, "file is larger than the 1 MiB limit"));
            }
            Ok(bytes) => {
                total = total.saturating_add(byte_len(bytes.len()));
                if total > MAX_TOTAL_BYTES {
                    errors.push(file_error(
                        &name,
                        "policy set exceeds the 8 MiB total limit",
                    ));
                    break;
                }
                files.push(SourceFile { name, bytes });
            }
            Err(err) => errors.push(file_error(&name, format!("cannot read file: {err}"))),
        }
    }

    build(files, errors)
}

pub(crate) fn build(
    mut files: Vec<SourceFile>,
    mut errors: Vec<LoadError>,
) -> Result<PolicySet, LoadErrors> {
    files.sort_by(|a, b| a.name.cmp(&b.name));
    let hash = hash_files(&files);
    let input_complete = errors.is_empty();
    let mut roles: Vec<Role> = Vec::new();
    let mut tests: Vec<AccessTest> = Vec::new();
    let mut role_origins: HashMap<String, (String, usize)> = HashMap::new();

    for file in &files {
        for (document, compiled) in parse_file(file, &mut errors) {
            match compiled {
                Compiled::Role(role) => {
                    if let Some((first_file, first_document)) = role_origins.get(&role.name) {
                        errors.push(document_error(
                            &file.name,
                            document,
                            format!(
                                "duplicate role name {:?}, first defined in {first_file} document {first_document}",
                                role.name
                            ),
                        ));
                    } else {
                        role_origins.insert(role.name.clone(), (file.name.clone(), document));
                        roles.push(*role);
                    }
                }
                Compiled::Tests(cases) => tests.extend(cases),
            }
        }
    }

    if errors.is_empty() {
        Ok(PolicySet { roles, tests, hash })
    } else {
        Err(LoadErrors::with_input_hash(
            errors,
            input_complete.then_some(hash),
        ))
    }
}

fn parse_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        duplicate_keys: DuplicateKeyPolicy::Error,
        merge_keys: MergeKeyPolicy::Error,
        strict_booleans: true,
        reject_unsupported_tags: true,
        with_snippet: false,
    }
}

struct ScanFailure {
    document: usize,
    message: String,
}

fn scan_documents(text: &str) -> Result<Vec<bool>, ScanFailure> {
    let mut documents: Vec<bool> = Vec::new();
    let mut awaiting_root = false;
    for item in Parser::new_from_str(text) {
        let (event, _) = item.map_err(|err| ScanFailure {
            document: documents.len().max(1),
            message: err.to_string(),
        })?;
        match event {
            Event::DocumentStart(..) => {
                documents.push(false);
                awaiting_root = true;
            }
            Event::Scalar(value, style, _, tag) if awaiting_root => {
                let explicit_null = tag
                    .as_deref()
                    .is_some_and(|tag| tag.core_suffix() == Some("null"));
                let plain_null = tag.is_none()
                    && style == ScalarStyle::Plain
                    && matches!(&*value, "" | "~" | "null" | "Null" | "NULL");
                let is_null = explicit_null || plain_null;
                if let Some(last) = documents.last_mut() {
                    *last = is_null;
                }
                awaiting_root = false;
            }
            Event::SequenceStart(..) | Event::MappingStart(..) | Event::Alias(_)
                if awaiting_root =>
            {
                awaiting_root = false;
            }
            _ => {}
        }
    }
    Ok(documents)
}

struct FileReport<'a> {
    name: &'a str,
    errors: &'a mut Vec<LoadError>,
    start: usize,
    truncated: bool,
}

impl<'a> FileReport<'a> {
    fn new(name: &'a str, errors: &'a mut Vec<LoadError>) -> Self {
        let start = errors.len();
        FileReport {
            name,
            errors,
            start,
            truncated: false,
        }
    }

    fn push(&mut self, error: LoadError) {
        if self.errors.len() - self.start >= MAX_ERRORS_PER_FILE {
            self.truncated = true;
        } else {
            self.errors.push(error);
        }
    }

    fn file(&mut self, message: impl Into<String>) {
        self.push(file_error(self.name, message));
    }

    fn document(&mut self, document: usize, message: impl Into<String>) {
        self.push(document_error(self.name, document, message));
    }

    fn finish(self) {
        if self.truncated {
            self.errors.push(file_error(
                self.name,
                format!(
                    "more than {MAX_ERRORS_PER_FILE} errors, the rest of the file was not checked"
                ),
            ));
        }
    }
}

fn parse_file(file: &SourceFile, errors: &mut Vec<LoadError>) -> Vec<(usize, Compiled)> {
    let mut report = FileReport::new(&file.name, errors);
    let compiled = parse_documents(file, &mut report);
    report.finish();
    compiled
}

fn parse_documents(file: &SourceFile, report: &mut FileReport<'_>) -> Vec<(usize, Compiled)> {
    let Ok(text) = std::str::from_utf8(&file.bytes) else {
        report.file("file is not valid UTF-8");
        return Vec::new();
    };

    let null_flags = match scan_documents(text) {
        Ok(flags) => flags,
        Err(failure) => {
            report.document(
                failure.document,
                format!("YAML syntax error: {}", failure.message),
            );
            return Vec::new();
        }
    };
    if null_flags.is_empty() {
        report.file("file contains no documents");
        return Vec::new();
    }

    let mut content_documents = Vec::new();
    for (index, is_null) in null_flags.iter().enumerate() {
        if report.truncated {
            return Vec::new();
        }
        if *is_null {
            report.document(index + 1, "document is empty or null");
        } else {
            content_documents.push(index + 1);
        }
    }

    let mut reader = text.as_bytes();
    let mut results =
        serde_saphyr::read_with_options::<_, RawDocument>(&mut reader, parse_options());
    let mut parsed = 0usize;
    let mut compiled_documents = Vec::new();
    for document in content_documents.iter().copied() {
        if report.truncated {
            return compiled_documents;
        }
        let Some(result) = results.next() else {
            break;
        };
        parsed += 1;
        match result {
            Err(err) => report.document(document, err.to_string()),
            Ok(raw) => {
                let source = format!("{} document {}", file.name, document);
                match raw.compile(&source) {
                    Ok(compiled) => compiled_documents.push((document, compiled)),
                    Err(messages) => {
                        for message in messages {
                            report.document(document, message);
                        }
                    }
                }
            }
        }
    }

    if !report.truncated && (parsed != content_documents.len() || results.next().is_some()) {
        report.file(format!(
            "document accounting mismatch: scanner found {} documents with content, parser produced {}",
            content_documents.len(),
            parsed
        ));
    }
    compiled_documents
}

#[cfg(test)]
mod tests {
    use super::{SourceFile, hash_files};

    fn files(names: &[&str]) -> Vec<SourceFile> {
        names
            .iter()
            .map(|name| SourceFile {
                name: (*name).to_owned(),
                bytes: format!("content of {name}").into_bytes(),
            })
            .collect()
    }

    #[test]
    fn hash_does_not_depend_on_input_order() {
        let sorted = [
            "a.yaml", "b.yaml", "b.yml", "c.yaml", "d.yaml", "e.yaml", "f.yml", "g.yaml", "h.yaml",
            "i.yaml", "j.yml", "k.yaml", "l.yaml",
        ];
        let scrambled = [
            "j.yml", "c.yaml", "l.yaml", "a.yaml", "h.yaml", "b.yml", "k.yaml", "e.yaml", "i.yaml",
            "b.yaml", "g.yaml", "f.yml", "d.yaml",
        ];
        assert_eq!(hash_files(&files(&sorted)), hash_files(&files(&scrambled)));
        assert_ne!(
            hash_files(&files(&sorted)),
            hash_files(&files(&sorted[..12]))
        );
    }
}
