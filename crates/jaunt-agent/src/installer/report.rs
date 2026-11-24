use std::io::{self, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
}

#[derive(Debug, Default)]
pub struct Report {
    lines: Vec<(Level, String)>,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn info(&mut self, text: impl Into<String>) {
        self.lines.push((Level::Info, text.into()));
    }

    pub fn warn(&mut self, text: impl Into<String>) {
        self.lines.push((Level::Warn, text.into()));
    }

    pub fn plan(&mut self, text: impl AsRef<str>) {
        self.info(format!("plan: {}", text.as_ref()));
    }

    pub fn plan_block(&mut self, content: &str) {
        for line in content.lines() {
            self.info(format!("    | {line}"));
        }
    }

    #[cfg(test)]
    pub fn contains(&self, level: Level, needle: &str) -> bool {
        self.lines
            .iter()
            .any(|(l, text)| *l == level && text.contains(needle))
    }

    pub fn write_to(&self, out: &mut impl Write, err: &mut impl Write) -> io::Result<()> {
        for (level, text) in &self.lines {
            match level {
                Level::Info => writeln!(out, "{text}")?,
                Level::Warn => writeln!(err, "warning: {text}")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Report;

    #[test]
    fn info_goes_to_stdout_and_warnings_to_stderr() {
        let mut report = Report::new();
        report.info("one");
        report.warn("two");
        report.plan("three");
        let mut out = Vec::new();
        let mut err = Vec::new();
        report.write_to(&mut out, &mut err).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "one\nplan: three\n");
        assert_eq!(String::from_utf8(err).unwrap(), "warning: two\n");
    }
}
