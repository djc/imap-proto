use std::borrow::Cow;
use std::marker::PhantomData;
use std::ops::{RangeFrom, RangeInclusive};
use std::str;

pub struct CommandBuilder {}

impl CommandBuilder {
    pub fn check() -> Command {
        let args = b"CHECK".to_vec();
        Command {
            args,
            next_state: None,
        }
    }

    pub fn close() -> Command {
        let args = b"CLOSE".to_vec();
        Command {
            args,
            next_state: Some(State::Authenticated),
        }
    }

    pub fn examine(mailbox: &str) -> SelectCommand<select::NoParams> {
        let args = format!("EXAMINE \"{}\"", quoted_string(mailbox).unwrap()).into_bytes();
        SelectCommand {
            args,
            state: PhantomData,
        }
    }

    pub fn fetch() -> FetchCommand<fetch::Empty> {
        FetchCommand {
            args: b"FETCH ".to_vec(),
            state: PhantomData,
        }
    }

    pub fn list(reference: &str, glob: &str) -> Command {
        let args = format!(
            "LIST \"{}\" \"{}\"",
            quoted_string(reference).unwrap(),
            quoted_string(glob).unwrap()
        )
        .into_bytes();
        Command {
            args,
            next_state: None,
        }
    }

    pub fn login(user_name: &str, password: &str) -> Command {
        let args = format!(
            "LOGIN \"{}\" \"{}\"",
            quoted_string(user_name).unwrap(),
            quoted_string(password).unwrap()
        )
        .into_bytes();
        Command {
            args,
            next_state: Some(State::Authenticated),
        }
    }

    pub fn select(mailbox: &str) -> SelectCommand<select::NoParams> {
        let args = format!("SELECT \"{}\"", quoted_string(mailbox).unwrap()).into_bytes();
        SelectCommand {
            args,
            state: PhantomData,
        }
    }

    pub fn uid_fetch() -> FetchCommand<fetch::Empty> {
        FetchCommand {
            args: b"UID FETCH ".to_vec(),
            state: PhantomData,
        }
    }
}

pub struct Command {
    pub args: Vec<u8>,
    pub next_state: Option<State>,
}

pub struct SelectCommand<T> {
    args: Vec<u8>,
    state: PhantomData<T>,
}

impl SelectCommand<select::NoParams> {
    // RFC 4551 CONDSTORE parameter (based on RFC 4466 `select-param`)
    pub fn cond_store(mut self) -> SelectCommand<select::Params> {
        self.args.extend(b" (CONDSTORE");
        SelectCommand {
            args: self.args,
            state: PhantomData,
        }
    }
}

impl From<SelectCommand<select::NoParams>> for Command {
    fn from(cmd: SelectCommand<select::NoParams>) -> Command {
        Command {
            args: cmd.args,
            next_state: Some(State::Selected),
        }
    }
}

impl From<SelectCommand<select::Params>> for Command {
    fn from(mut cmd: SelectCommand<select::Params>) -> Command {
        cmd.args.push(b')');
        Command {
            args: cmd.args,
            next_state: Some(State::Selected),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

pub mod select {
    pub struct NoParams;
    pub struct Params;
}

pub mod fetch {
    pub struct Empty;
    pub struct Messages;
    pub struct Attributes;
    pub struct Modifiers;
}

pub struct FetchCommand<T> {
    args: Vec<u8>,
    state: PhantomData<T>,
}

impl FetchCommand<fetch::Empty> {
    pub fn num(mut self, num: u32) -> FetchCommand<fetch::Messages> {
        sequence_num(&mut self.args, num);
        FetchCommand {
            args: self.args,
            state: PhantomData,
        }
    }

    pub fn range(mut self, range: RangeInclusive<u32>) -> FetchCommand<fetch::Messages> {
        sequence_range(&mut self.args, range);
        FetchCommand {
            args: self.args,
            state: PhantomData,
        }
    }

    pub fn range_from(mut self, range: RangeFrom<u32>) -> FetchCommand<fetch::Messages> {
        range_from(&mut self.args, range);
        FetchCommand {
            args: self.args,
            state: PhantomData,
        }
    }
}

impl FetchCommand<fetch::Messages> {
    pub fn num(mut self, num: u32) -> FetchCommand<fetch::Messages> {
        self.args.extend(b",");
        sequence_num(&mut self.args, num);
        self
    }

    pub fn range(mut self, range: RangeInclusive<u32>) -> FetchCommand<fetch::Messages> {
        self.args.extend(b",");
        sequence_range(&mut self.args, range);
        self
    }

    pub fn range_from(mut self, range: RangeFrom<u32>) -> FetchCommand<fetch::Messages> {
        self.args.extend(b",");
        range_from(&mut self.args, range);
        self
    }

    pub fn attr_macro(mut self, named: AttrMacro) -> FetchCommand<fetch::Modifiers> {
        self.args.push(b' ');
        self.args.extend(
            match named {
                AttrMacro::All => "ALL",
                AttrMacro::Fast => "FAST",
                AttrMacro::Full => "FULL",
            }
            .as_bytes(),
        );
        FetchCommand {
            args: self.args,
            state: PhantomData,
        }
    }

    pub fn attr(mut self, attr: Attribute) -> FetchCommand<fetch::Attributes> {
        self.args.extend(b" (");
        push_attr(&mut self.args, attr);
        FetchCommand {
            args: self.args,
            state: PhantomData,
        }
    }
}

fn sequence_num(cmd: &mut Vec<u8>, num: u32) {
    cmd.extend(num.to_string().as_bytes());
}

fn sequence_range(cmd: &mut Vec<u8>, range: RangeInclusive<u32>) {
    cmd.extend(range.start().to_string().as_bytes());
    cmd.push(b':');
    cmd.extend(range.end().to_string().as_bytes());
}

fn range_from(cmd: &mut Vec<u8>, range: RangeFrom<u32>) {
    cmd.extend(range.start.to_string().as_bytes());
    cmd.extend(b":*");
}

impl FetchCommand<fetch::Attributes> {
    pub fn attr(mut self, attr: Attribute) -> FetchCommand<fetch::Attributes> {
        self.args.push(b' ');
        push_attr(&mut self.args, attr);
        self
    }

    pub fn changed_since(mut self, seq: u64) -> FetchCommand<fetch::Modifiers> {
        self.args.push(b')');
        changed_since(&mut self.args, seq);
        FetchCommand {
            args: self.args,
            state: PhantomData,
        }
    }
}

fn push_attr(cmd: &mut Vec<u8>, attr: Attribute) {
    cmd.extend(
        match attr {
            Attribute::Body => "BODY",
            Attribute::Envelope => "ENVELOPE",
            Attribute::Flags => "FLAGS",
            Attribute::InternalDate => "INTERNALDATE",
            Attribute::ModSeq => "MODSEQ",
            Attribute::Rfc822 => "RFC822",
            Attribute::Rfc822Size => "RFC822.SIZE",
            Attribute::Rfc822Text => "RFC822.TEXT",
            Attribute::Uid => "UID",
            Attribute::GmailLabels => "X-GM-LABELS",
            Attribute::GmailMsgId => "X-GM-MSGID",
            Attribute::GmailThrId => "X-GM-THRID",
        }
        .as_bytes(),
    );
}

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Attribute {
    Body,
    Envelope,
    Flags,
    InternalDate,
    ModSeq, // RFC 4551, section 3.3.2
    Rfc822,
    Rfc822Size,
    Rfc822Text,
    Uid,
    /// <https://developers.google.com/gmail/imap/imap-extensions#access_to_gmail_labels_x-gm-labels>
    GmailLabels,
    GmailMsgId,
    GmailThrId,
}

impl From<FetchCommand<fetch::Attributes>> for Command {
    fn from(mut cmd: FetchCommand<fetch::Attributes>) -> Command {
        cmd.args.push(b')');
        Command {
            args: cmd.args,
            next_state: None,
        }
    }
}

impl From<FetchCommand<fetch::Modifiers>> for Command {
    fn from(cmd: FetchCommand<fetch::Modifiers>) -> Command {
        Command {
            args: cmd.args,
            next_state: None,
        }
    }
}

impl FetchCommand<fetch::Modifiers> {
    pub fn changed_since(mut self, seq: u64) -> FetchCommand<fetch::Modifiers> {
        changed_since(&mut self.args, seq);
        self
    }
}

fn changed_since(cmd: &mut Vec<u8>, seq: u64) {
    cmd.extend(b" (CHANGEDSINCE ");
    cmd.extend(seq.to_string().as_bytes());
    cmd.push(b')');
}

/// Returns an escaped string if necessary for use as a "quoted" string per
/// the IMAPv4 RFC. Return value does not include surrounding quote characters.
/// Will return Err if the argument contains illegal characters.
///
/// Relevant definitions from RFC 3501 formal syntax:
///
/// string = quoted / literal [literal elided here]
/// quoted = DQUOTE *QUOTED-CHAR DQUOTE
/// QUOTED-CHAR = <any TEXT-CHAR except quoted-specials> / "\" quoted-specials
/// quoted-specials = DQUOTE / "\"
/// TEXT-CHAR = <any CHAR except CR and LF>
fn quoted_string(s: &str) -> Result<Cow<'_, str>, &'static str> {
    let bytes = s.as_bytes();
    let (mut start, mut new) = (0, Vec::<u8>::new());
    for (i, b) in bytes.iter().enumerate() {
        match *b {
            b'\r' | b'\n' => {
                return Err("CR and LF not allowed in quoted strings");
            }
            b'\\' | b'"' => {
                if start < i {
                    new.extend(&bytes[start..i]);
                }
                new.push(b'\\');
                new.push(*b);
                start = i + 1;
            }
            _ => {}
        };
    }
    if start == 0 {
        Ok(Cow::Borrowed(s))
    } else {
        if start < bytes.len() {
            new.extend(&bytes[start..]);
        }
        // Since the argument is a str, it must contain valid UTF-8. Since
        // this function's transformation preserves the UTF-8 validity,
        // unwrapping here should be okay.
        Ok(Cow::Owned(String::from_utf8(new).unwrap()))
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttrMacro {
    All,
    Fast,
    Full,
}

#[cfg(test)]
mod tests {
    use super::{quoted_string, Attribute, Command, CommandBuilder};

    #[test]
    fn login() {
        assert_eq!(
            CommandBuilder::login("djc", "s3cr3t").args,
            b"LOGIN \"djc\" \"s3cr3t\""
        );
        assert_eq!(
            CommandBuilder::login("djc", "domain\\password").args,
            b"LOGIN \"djc\" \"domain\\\\password\""
        );
    }

    #[test]
    fn select() {
        let cmd = Command::from(CommandBuilder::select("INBOX"));
        assert_eq!(&cmd.args, br#"SELECT "INBOX""#);
        let cmd = Command::from(CommandBuilder::examine("INBOX").cond_store());
        assert_eq!(&cmd.args, br#"EXAMINE "INBOX" (CONDSTORE)"#);
    }

    #[test]
    fn fetch() {
        let cmd: Command = CommandBuilder::fetch()
            .range_from(1..)
            .attr(Attribute::Uid)
            .attr(Attribute::ModSeq)
            .changed_since(13)
            .into();
        assert_eq!(cmd.args, &b"FETCH 1:* (UID MODSEQ) (CHANGEDSINCE 13)"[..]);

        let cmd: Command = CommandBuilder::fetch()
            .num(1)
            .num(2)
            .attr(Attribute::Uid)
            .attr(Attribute::ModSeq)
            .into();
        assert_eq!(cmd.args, &b"FETCH 1,2 (UID MODSEQ)"[..]);
    }

    #[test]
    fn test_quoted_string() {
        assert_eq!(quoted_string("a").unwrap(), "a");
        assert_eq!(quoted_string("").unwrap(), "");
        assert_eq!(quoted_string("a\"b\\c").unwrap(), "a\\\"b\\\\c");
        assert_eq!(quoted_string("\"foo\\").unwrap(), "\\\"foo\\\\");
        assert!(quoted_string("\n").is_err());
    }
}
