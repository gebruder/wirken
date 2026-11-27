//! The log writer for every command but `wirken chat`: each log event
//! on one line of stdout.
//!
//! A log event can carry text a model chose: a tool name, a reason a
//! provider gave. The formatter escapes the escape sequences in it, and
//! not its line breaks, so one event could print lines of the model's
//! choosing on the terminal where `wirken ask` and `wirken lyrik` put
//! an approval prompt. Folded, the event is one line after its
//! timestamp and level, and cannot draw a line that reads as the
//! prompt or as a card.

use std::io::Write;

/// The writer `main` installs.
pub fn writer() -> OneLineLogs {
    OneLineLogs
}

pub struct OneLineLogs;

impl Write for OneLineLogs {
    /// One event arrives as one write of the whole formatted line.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut out = std::io::stdout().lock();
        out.write_all(&fold(buf))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

/// `event` with every line break but a final one written out as `\n`,
/// and every carriage return as `\r`.
fn fold(event: &[u8]) -> Vec<u8> {
    let (body, end): (&[u8], &[u8]) = match event.strip_suffix(b"\n") {
        Some(body) => (body, b"\n"),
        None => (event, b""),
    };
    let mut out = Vec::with_capacity(event.len() + 8);
    for &b in body {
        match b {
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b => out.push(b),
        }
    }
    out.extend_from_slice(end);
    out
}

#[cfg(test)]
mod tests {
    use super::fold;

    #[test]
    fn an_event_is_one_line() {
        let event = b"WARN wirken_agent::runtime: tool=exec\r\nrequest: agent default requests exec (tier2)\napprove? [y/N]: \n";
        let folded = fold(event);
        assert_eq!(
            folded,
            b"WARN wirken_agent::runtime: tool=exec\\r\\nrequest: agent default requests exec (tier2)\\napprove? [y/N]: \n"
        );
        assert_eq!(folded.iter().filter(|b| **b == b'\n').count(), 1);
    }

    #[test]
    fn a_plain_event_is_unchanged() {
        assert_eq!(fold(b"INFO a: b\n"), b"INFO a: b\n");
        assert_eq!(fold(b"no newline"), b"no newline");
    }

    /// Through the subscriber, as `main` installs it: a field holding
    /// line breaks comes out on the event's one line.
    #[test]
    fn the_subscriber_writes_a_field_with_line_breaks_on_one_line() {
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Kept(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Kept {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(&fold(buf));
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let kept = Kept::default();
        let sink = kept.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let name = "exec\nrequest: agent default requests exec (tier2)\napprove? [y/N]: ";
            // The two shapes that print a value as written: a field
            // formatted with `%`, and a value in the message.
            tracing::warn!(tool = %name, "refusing the call");
            tracing::warn!("Permission denied: tool '{}' requires tier3", name);
        });
        let text = String::from_utf8(kept.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 2, "one line per event: {text}");
        assert!(text.contains("tool=exec\\nrequest:"), "{text}");
        assert!(text.contains("tool 'exec\\nrequest:"), "{text}");
    }
}
