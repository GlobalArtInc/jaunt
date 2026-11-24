use std::io::{self, BufRead, IsTerminal, Write};

pub trait ConsentPrompt {
    fn interactive(&self) -> bool;
    fn confirm(&self, question: &str) -> io::Result<bool>;
}

pub struct TerminalPrompt;

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

impl ConsentPrompt for TerminalPrompt {
    fn interactive(&self) -> bool {
        io::stdin().is_terminal() && io::stderr().is_terminal()
    }

    fn confirm(&self, question: &str) -> io::Result<bool> {
        let mut stderr = io::stderr().lock();
        write!(stderr, "{question} ")?;
        stderr.flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        Ok(is_yes(&answer))
    }
}

#[cfg(test)]
mod tests {
    use super::is_yes;

    #[test]
    fn only_an_explicit_yes_is_consent() {
        for (answer, expected) in [
            ("y\n", true),
            ("Y", true),
            ("yes\n", true),
            (" YES \r\n", true),
            ("", false),
            ("\n", false),
            ("n", false),
            ("no", false),
            ("yep", false),
            ("ye", false),
        ] {
            assert_eq!(is_yes(answer), expected, "{answer:?}");
        }
    }
}
