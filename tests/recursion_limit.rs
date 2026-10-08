//! Body-structure parsing must not exhaust the stack on deeply nested input.
//!
//! The body-structure grammar has three recursion cycles (multipart nesting,
//! `message/rfc822` nesting, and body-extension list nesting). A stack overflow
//! aborts the whole process and cannot be caught, so each deep-parse case runs
//! in a child process: the test binary re-invokes itself, running only
//! `deep_parse_child` with the case described in environment variables. The
//! parent then checks how the child ended.
//!
//! The child parses on a 2 MiB stack, the default for a Tokio worker thread.

use imap_proto::{AttributeValue, BodyExtension, BodyStructure, Response};
use std::process::Command;

const ENVELOPE: &str = "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";
const TEXT_PART: &str = "(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 1 1)";

const CYCLE_VAR: &str = "IMAP_PROTO_TEST_CYCLE";
const DEPTH_VAR: &str = "IMAP_PROTO_TEST_DEPTH";
const CHILD_STACK_BYTES: usize = 2 * 1024 * 1024;

// Depths chosen to be far beyond where a 2 MiB stack is exhausted in both debug
// and release builds, so that the tests fail on an unbounded parser regardless
// of build profile.
const MULTIPART_ABORT_DEPTH: usize = 10_000;
const MESSAGE_ABORT_DEPTH: usize = 2_000;
const EXTENSION_ABORT_DEPTH: usize = 50_000;

// Real-world MIME nests around a dozen levels at most; a fix must not reject this.
const REALISTIC_DEPTH: usize = 10;

#[derive(Clone, Copy, Debug)]
enum Cycle {
    /// `(` repeated and never closed: the cheapest payload, and not well-formed.
    MultipartUnclosed,
    /// Well-formed `((( text ) "MIXED") "MIXED")` nesting.
    MultipartClosed,
    /// Well-formed `message/rfc822` parts nested inside one another. Never has
    /// two adjacent `(` in the nesting path.
    Message,
    /// A multipart whose trailing extension data is a deeply nested list.
    Extension,
}

impl Cycle {
    fn name(self) -> &'static str {
        match self {
            Cycle::MultipartUnclosed => "multipart-unclosed",
            Cycle::MultipartClosed => "multipart-closed",
            Cycle::Message => "message",
            Cycle::Extension => "extension",
        }
    }

    fn from_name(name: &str) -> Cycle {
        [
            Cycle::MultipartUnclosed,
            Cycle::MultipartClosed,
            Cycle::Message,
            Cycle::Extension,
        ]
        .into_iter()
        .find(|c| c.name() == name)
        .unwrap_or_else(|| panic!("unknown cycle {name:?}"))
    }

    fn body(self, depth: usize) -> String {
        match self {
            Cycle::MultipartUnclosed => "(".repeat(depth),
            Cycle::MultipartClosed => {
                let mut part = TEXT_PART.to_string();
                for _ in 0..depth {
                    part = format!("({part} \"MIXED\")");
                }
                part
            }
            Cycle::Message => {
                let mut part = TEXT_PART.to_string();
                for _ in 0..depth {
                    part = format!(
                        "(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 1 {ENVELOPE} {part} 1)"
                    );
                }
                part
            }
            Cycle::Extension => format!(
                "({TEXT_PART} \"MIXED\" NIL NIL NIL NIL {}1{})",
                "(".repeat(depth),
                ")".repeat(depth)
            ),
        }
    }

    fn response(self, depth: usize) -> Vec<u8> {
        format!("* 1 FETCH (BODYSTRUCTURE {})\r\n", self.body(depth)).into_bytes()
    }
}

/// Runs inside the child process only; ignored in normal runs.
///
/// Passes if the parser returns an error, rather than overflowing the stack
/// (which kills the process before this test can report anything). The result
/// must not be `Incomplete`: streaming callers treat that as "read more bytes
/// and retry", which would turn an abort into an unbounded buffering loop.
#[test]
#[ignore = "run by the parent tests in a child process"]
fn deep_parse_child() {
    let cycle = Cycle::from_name(&std::env::var(CYCLE_VAR).expect("missing cycle"));
    let depth: usize = std::env::var(DEPTH_VAR)
        .expect("missing depth")
        .parse()
        .expect("depth must be a number");
    let payload = cycle.response(depth);

    let outcome = std::thread::Builder::new()
        .stack_size(CHILD_STACK_BYTES)
        .spawn(move || match Response::parse(&payload) {
            Ok(_) => Err("parser accepted input nested beyond any sane limit".to_string()),
            Err(nom::Err::Incomplete(needed)) => Err(format!(
                "parser returned Incomplete ({needed:?}); a streaming caller would wait for more data"
            )),
            Err(_) => Ok(()),
        })
        .expect("failed to spawn parser thread")
        .join()
        .expect("parser thread panicked");

    if let Err(message) = outcome {
        panic!("{message}");
    }
}

fn assert_deep_input_rejected(cycle: Cycle, depth: usize) {
    let exe = std::env::current_exe().unwrap();
    let child_args = ["--ignored", "--exact", "deep_parse_child", "--nocapture"];

    // The child is expected to abort on an unfixed parser; keep it from leaving core dumps behind.
    #[cfg(unix)]
    let mut command = {
        let mut c = Command::new("sh");
        c.args(["-c", "ulimit -c 0; exec \"$0\" \"$@\""]).arg(&exe);
        c
    };
    #[cfg(not(unix))]
    let mut command = Command::new(&exe);

    let output = command
        .args(child_args)
        .env(CYCLE_VAR, cycle.name())
        .env(DEPTH_VAR, depth.to_string())
        .output()
        .expect("failed to spawn child test process");

    if output.status.success() {
        return;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("overflowed its stack") {
        panic!(
            "{cycle:?} nesting of depth {depth} overflowed the stack and aborted the process \
             (status: {}); the parser needs a nesting limit",
            output.status
        );
    }
    panic!(
        "{cycle:?} nesting of depth {depth} was not rejected cleanly (status: {})\n--- stdout ---\n{}\n--- stderr ---\n{stderr}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
fn deeply_nested_unclosed_multipart_is_rejected() {
    assert_deep_input_rejected(Cycle::MultipartUnclosed, MULTIPART_ABORT_DEPTH);
}

#[test]
fn deeply_nested_closed_multipart_is_rejected() {
    assert_deep_input_rejected(Cycle::MultipartClosed, MULTIPART_ABORT_DEPTH);
}

#[test]
fn deeply_nested_message_rfc822_is_rejected() {
    assert_deep_input_rejected(Cycle::Message, MESSAGE_ABORT_DEPTH);
}

#[test]
fn deeply_nested_body_extension_is_rejected() {
    assert_deep_input_rejected(Cycle::Extension, EXTENSION_ABORT_DEPTH);
}

fn parse_body(cycle: Cycle, depth: usize) -> BodyStructure<'static> {
    let payload = cycle.response(depth);
    match Response::parse(&payload) {
        Ok((_, Response::Fetch(_, attrs))) => attrs
            .into_iter()
            .find_map(|a| match a {
                AttributeValue::BodyStructure(body) => Some(body.into_owned()),
                _ => None,
            })
            .expect("no BODYSTRUCTURE attribute"),
        other => panic!("{cycle:?} at depth {depth} should parse, got {other:?}"),
    }
}

fn nesting_of(body: &BodyStructure<'_>) -> usize {
    match body {
        BodyStructure::Multipart { bodies, .. } => 1 + bodies.iter().map(nesting_of).max().unwrap(),
        BodyStructure::Message { body, .. } => 1 + nesting_of(body),
        _ => 0,
    }
}

// The tests below pass today. They guard against a fix that rejects realistic input.

#[test]
fn realistic_multipart_nesting_still_parses() {
    let body = parse_body(Cycle::MultipartClosed, REALISTIC_DEPTH);
    assert_eq!(nesting_of(&body), REALISTIC_DEPTH);
}

#[test]
fn realistic_message_rfc822_nesting_still_parses() {
    let body = parse_body(Cycle::Message, REALISTIC_DEPTH);
    assert_eq!(nesting_of(&body), REALISTIC_DEPTH);
}

#[test]
fn realistic_body_extension_nesting_still_parses() {
    let body = parse_body(Cycle::Extension, REALISTIC_DEPTH);
    let BodyStructure::Multipart { extension, .. } = body else {
        panic!("expected a multipart body");
    };
    let mut depth = 0;
    let mut current = extension.as_ref();
    while let Some(BodyExtension::List(items)) = current {
        depth += 1;
        current = items.first();
    }
    assert_eq!(depth, REALISTIC_DEPTH);
}
