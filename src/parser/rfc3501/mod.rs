//!
//! https://tools.ietf.org/html/rfc3501
//!
//! INTERNET MESSAGE ACCESS PROTOCOL
//!

use std::borrow::Cow;
use std::str::from_utf8;

use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while1},
    character::streaming::char,
    combinator::{map, map_res, opt, recognize, value},
    multi::{many0, many1},
    sequence::{delimited, pair, preceded, terminated},
    IResult, Parser,
};

use crate::parser::{
    core::*, rfc2087, rfc2971, rfc3501::body::*, rfc3501::body_structure::*, rfc4314, rfc4315,
    rfc4315::UidSetMember, rfc4551, rfc5161, rfc5256, rfc5464, rfc5464::Metadata, rfc7162,
    Response,
};

use super::gmail;

pub mod body;
pub mod body_structure;

fn is_tag_char(c: u8) -> bool {
    c != b'+' && is_astring_char(c)
}

fn status_ok(i: &[u8]) -> IResult<&[u8], Status> {
    map(tag_no_case("OK"), |_s| Status::Ok).parse(i)
}
fn status_no(i: &[u8]) -> IResult<&[u8], Status> {
    map(tag_no_case("NO"), |_s| Status::No).parse(i)
}
fn status_bad(i: &[u8]) -> IResult<&[u8], Status> {
    map(tag_no_case("BAD"), |_s| Status::Bad).parse(i)
}
fn status_preauth(i: &[u8]) -> IResult<&[u8], Status> {
    map(tag_no_case("PREAUTH"), |_s| Status::PreAuth).parse(i)
}
fn status_bye(i: &[u8]) -> IResult<&[u8], Status> {
    map(tag_no_case("BYE"), |_s| Status::Bye).parse(i)
}

#[derive(Debug, Eq, PartialEq)]
pub enum Status {
    Ok,
    No,
    Bad,
    PreAuth,
    Bye,
}

fn status(i: &[u8]) -> IResult<&[u8], Status> {
    alt((status_ok, status_no, status_bad, status_preauth, status_bye)).parse(i)
}

pub(crate) fn mailbox(i: &[u8]) -> IResult<&[u8], Cow<'_, str>> {
    map(astring_utf8, |s| {
        if s.eq_ignore_ascii_case("INBOX") {
            Cow::Borrowed("INBOX")
        } else {
            s
        }
    })
    .parse(i)
}

fn flag_extension(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        recognize(pair(tag("\\"), take_while(is_atom_char))),
        from_utf8,
    )
    .parse(i)
}

pub(crate) fn flag(i: &[u8]) -> IResult<&[u8], &str> {
    // Correct code is
    //   alt((flag_extension, atom))(i)
    //
    // Unfortunately, some unknown providers send the following response:
    // * FLAGS (OIB-Seen-[Gmail]/All)
    //
    // As a workaround, ']' (resp-specials) is allowed here.
    alt((
        flag_extension,
        map_res(take_while1(is_astring_char), from_utf8),
    ))
    .parse(i)
}

fn flag_list(i: &[u8]) -> IResult<&[u8], Vec<Cow<'_, str>>> {
    // Correct code is
    //   parenthesized_list(flag)(i)
    //
    // Unfortunately, Zoho Mail Server (imap.zoho.com) sends the following response:
    // * FLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)
    //
    // As a workaround, "\*" is allowed here.
    //
    // Also, surgemail sends an additional space before the closing bracket:
    // * FLAGS (\Answered \Flagged \Deleted \Draft \Seen $Forwarded )
    //
    // As a workaround, optional spaces before the closing bracket are allowed.
    parenthesized_list(map(flag_perm, Cow::Borrowed)).parse(i)
}

fn flag_perm(i: &[u8]) -> IResult<&[u8], &str> {
    alt((map_res(tag("\\*"), from_utf8), flag)).parse(i)
}

fn resp_text_code_alert(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(tag_no_case("ALERT"), |_| ResponseCode::Alert).parse(i)
}

fn resp_text_code_badcharset(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(
        preceded(
            tag_no_case("BADCHARSET"),
            opt(preceded(
                tag(" "),
                parenthesized_nonempty_list(astring_utf8),
            )),
        ),
        ResponseCode::BadCharset,
    )
    .parse(i)
}

fn resp_text_code_capability(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(capability_data, ResponseCode::Capabilities).parse(i)
}

fn resp_text_code_parse(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(tag_no_case("PARSE"), |_| ResponseCode::Parse).parse(i)
}

fn resp_text_code_permanent_flags(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(
        preceded(
            tag_no_case("PERMANENTFLAGS "),
            parenthesized_list(map(flag_perm, Cow::Borrowed)),
        ),
        ResponseCode::PermanentFlags,
    )
    .parse(i)
}

fn resp_text_code_read_only(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(tag_no_case("READ-ONLY"), |_| ResponseCode::ReadOnly).parse(i)
}

fn resp_text_code_read_write(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(tag_no_case("READ-WRITE"), |_| ResponseCode::ReadWrite).parse(i)
}

fn resp_text_code_try_create(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(tag_no_case("TRYCREATE"), |_| ResponseCode::TryCreate).parse(i)
}

fn resp_text_code_uid_validity(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(
        preceded(tag_no_case("UIDVALIDITY "), number),
        ResponseCode::UidValidity,
    )
    .parse(i)
}

fn resp_text_code_uid_next(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(
        preceded(tag_no_case("UIDNEXT "), number),
        ResponseCode::UidNext,
    )
    .parse(i)
}

fn resp_text_code_unseen(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(
        preceded(tag_no_case("UNSEEN "), number),
        ResponseCode::Unseen,
    )
    .parse(i)
}

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResponseCode<'a> {
    Alert,
    BadCharset(Option<Vec<Cow<'a, str>>>),
    Capabilities(Vec<Capability<'a>>),
    HighestModSeq(u64), // RFC 4551, section 3.1.1
    Parse,
    PermanentFlags(Vec<Cow<'a, str>>),
    ReadOnly,
    ReadWrite,
    TryCreate,
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
    AppendUid(u32, Vec<UidSetMember>),
    CopyUid(u32, Vec<UidSetMember>, Vec<UidSetMember>),
    UidNotSticky,
    MetadataLongEntries(u64), // RFC 5464, section 4.2.1
    MetadataMaxSize(u64),     // RFC 5464, section 4.3
    MetadataTooMany,          // RFC 5464, section 4.3
    MetadataNoPrivate,        // RFC 5464, section 4.3
}

impl<'a> ResponseCode<'a> {
    pub fn into_owned(self) -> ResponseCode<'static> {
        match self {
            ResponseCode::Alert => ResponseCode::Alert,
            ResponseCode::BadCharset(v) => {
                ResponseCode::BadCharset(v.map(|vs| vs.into_iter().map(to_owned_cow).collect()))
            }
            ResponseCode::Capabilities(v) => {
                ResponseCode::Capabilities(v.into_iter().map(Capability::into_owned).collect())
            }
            ResponseCode::HighestModSeq(v) => ResponseCode::HighestModSeq(v),
            ResponseCode::Parse => ResponseCode::Parse,
            ResponseCode::PermanentFlags(v) => {
                ResponseCode::PermanentFlags(v.into_iter().map(to_owned_cow).collect())
            }
            ResponseCode::ReadOnly => ResponseCode::ReadOnly,
            ResponseCode::ReadWrite => ResponseCode::ReadWrite,
            ResponseCode::TryCreate => ResponseCode::TryCreate,
            ResponseCode::UidNext(v) => ResponseCode::UidNext(v),
            ResponseCode::UidValidity(v) => ResponseCode::UidValidity(v),
            ResponseCode::Unseen(v) => ResponseCode::Unseen(v),
            ResponseCode::AppendUid(a, b) => ResponseCode::AppendUid(a, b),
            ResponseCode::CopyUid(a, b, c) => ResponseCode::CopyUid(a, b, c),
            ResponseCode::UidNotSticky => ResponseCode::UidNotSticky,
            ResponseCode::MetadataLongEntries(v) => ResponseCode::MetadataLongEntries(v),
            ResponseCode::MetadataMaxSize(v) => ResponseCode::MetadataMaxSize(v),
            ResponseCode::MetadataTooMany => ResponseCode::MetadataTooMany,
            ResponseCode::MetadataNoPrivate => ResponseCode::MetadataNoPrivate,
        }
    }
}

fn resp_text_code(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    // Per the spec, the closing tag should be "] ".
    // See `resp_text` for more on why this is done differently.
    delimited(
        tag("["),
        alt((
            resp_text_code_alert,
            resp_text_code_badcharset,
            resp_text_code_capability,
            resp_text_code_parse,
            resp_text_code_permanent_flags,
            resp_text_code_uid_validity,
            resp_text_code_uid_next,
            resp_text_code_unseen,
            resp_text_code_read_only,
            resp_text_code_read_write,
            resp_text_code_try_create,
            rfc4551::resp_text_code_highest_mod_seq,
            rfc4315::resp_text_code_append_uid,
            rfc4315::resp_text_code_copy_uid,
            rfc4315::resp_text_code_uid_not_sticky,
            rfc5464::resp_text_code_metadata_long_entries,
            rfc5464::resp_text_code_metadata_max_size,
            rfc5464::resp_text_code_metadata_too_many,
            rfc5464::resp_text_code_metadata_no_private,
        )),
        tag("]"),
    )
    .parse(i)
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum Capability<'a> {
    Imap4rev1,
    Auth(Cow<'a, str>),
    Atom(Cow<'a, str>),
}

impl<'a> Capability<'a> {
    pub fn into_owned(self) -> Capability<'static> {
        match self {
            Capability::Imap4rev1 => Capability::Imap4rev1,
            Capability::Auth(v) => Capability::Auth(to_owned_cow(v)),
            Capability::Atom(v) => Capability::Atom(to_owned_cow(v)),
        }
    }
}

fn capability(i: &[u8]) -> IResult<&[u8], Capability<'_>> {
    alt((
        map(tag_no_case("IMAP4rev1"), |_| Capability::Imap4rev1),
        map(
            map(preceded(tag_no_case("AUTH="), atom), Cow::Borrowed),
            Capability::Auth,
        ),
        map(map(atom, Cow::Borrowed), Capability::Atom),
    ))
    .parse(i)
}

fn ensure_capabilities_contains_imap4rev(
    capabilities: Vec<Capability<'_>>,
) -> Result<Vec<Capability<'_>>, ()> {
    if capabilities.contains(&Capability::Imap4rev1) {
        Ok(capabilities)
    } else {
        Err(())
    }
}

fn capability_data(i: &[u8]) -> IResult<&[u8], Vec<Capability<'_>>> {
    map_res(
        preceded(
            tag_no_case("CAPABILITY"),
            many0(preceded(char(' '), capability)),
        ),
        ensure_capabilities_contains_imap4rev,
    )
    .parse(i)
}

fn mailbox_data_search(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(
        // Technically, trailing whitespace is not allowed here, but multiple
        // email servers in the wild seem to have it anyway (see #34, #108).
        terminated(
            preceded(tag_no_case("SEARCH"), many0(preceded(tag(" "), number))),
            opt(tag(" ")),
        ),
        MailboxDatum::Search,
    )
    .parse(i)
}

fn mailbox_data_flags(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(
        preceded(tag_no_case("FLAGS "), flag_list),
        MailboxDatum::Flags,
    )
    .parse(i)
}

fn mailbox_data_exists(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(
        terminated(number, tag_no_case(" EXISTS")),
        MailboxDatum::Exists,
    )
    .parse(i)
}

/// The name attributes are returned as part of a LIST response described in
/// [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2).
///
/// This enumeration additional includes values from the extension Special-Use
/// Mailboxes [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2).
#[derive(Debug, Eq, PartialEq, Clone)]
#[non_exhaustive]
pub enum NameAttribute<'a> {
    /// From [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2):
    ///
    /// > It is not possible for any child levels of hierarchy to exist
    /// > under this name; no child levels exist now and none can be
    /// > created in the future.
    NoInferiors,
    /// From [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2):
    ///
    /// > It is not possible to use this name as a selectable mailbox.
    NoSelect,
    /// From [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2):
    ///
    /// > The mailbox has been marked "interesting" by the server; the
    /// > mailbox probably contains messages that have been added since
    /// > the last time the mailbox was selected.
    Marked,
    /// From [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2):
    ///
    /// > The mailbox does not contain any additional messages since the
    /// > last time the mailbox was selected.
    Unmarked,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox presents all messages in the user's message store.
    /// > Implementations MAY omit some messages, such as, perhaps, those
    /// > in \Trash and \Junk.  When this special use is supported, it is
    /// > almost certain to represent a virtual mailbox.
    All,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox is used to archive messages.  The meaning of an
    /// > "archival" mailbox is server-dependent; typically, it will be
    /// > used to get messages out of the inbox, or otherwise keep them
    /// > out of the user's way, while still making them accessible.
    Archive,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox is used to hold draft messages -- typically,
    /// > messages that are being composed but have not yet been sent.  In
    /// > some server implementations, this might be a virtual mailbox,
    /// > containing messages from other mailboxes that are marked with
    /// > the "\Draft" message flag.  Alternatively, this might just be
    /// > advice that a client put drafts here.
    Drafts,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox presents all messages marked in some way as
    /// > "important".  When this special use is supported, it is likely
    /// > to represent a virtual mailbox collecting messages (from other
    /// > mailboxes) that are marked with the "\Flagged" message flag.
    Flagged,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox is where messages deemed to be junk mail are held.
    /// > Some server implementations might put messages here
    /// > automatically.  Alternatively, this might just be advice to a
    /// > client-side spam filter.
    Junk,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2):
    ///
    /// > This mailbox is used to hold copies of messages that have been
    /// > sent.  Some server implementations might put messages here
    /// > automatically.  Alternatively, this might just be advice that a
    /// > client save sent messages here.
    Sent,
    /// From [RFC 6154 section 2](https://tools.ietf.org/html/rfc6154#section-2)
    ///
    /// > This mailbox is used to hold messages that have been deleted or
    /// > marked for deletion.  In some server implementations, this might
    /// > be a virtual mailbox, containing messages from other mailboxes
    /// > that are marked with the "\Deleted" message flag.
    /// > Alternatively, this might just be advice that a client that
    /// > chooses not to use the IMAP "\Deleted" model should use this as
    /// > its trash location.  In server implementations that strictly
    /// > expect the IMAP "\Deleted" model, this special use is likely not
    /// > to be supported.
    Trash,
    /// A name attribute not defined in [RFC 3501 section 7.2.2](https://tools.ietf.org/html/rfc3501#section-7.2.2)
    /// or any supported extension.
    Extension(Cow<'a, str>),
}

impl<'a> NameAttribute<'a> {
    pub fn into_owned(self) -> NameAttribute<'static> {
        match self {
            // RFC 3501
            NameAttribute::NoInferiors => NameAttribute::NoInferiors,
            NameAttribute::NoSelect => NameAttribute::NoSelect,
            NameAttribute::Marked => NameAttribute::Marked,
            NameAttribute::Unmarked => NameAttribute::Unmarked,
            // RFC 6154
            NameAttribute::All => NameAttribute::All,
            NameAttribute::Archive => NameAttribute::Archive,
            NameAttribute::Drafts => NameAttribute::Drafts,
            NameAttribute::Flagged => NameAttribute::Flagged,
            NameAttribute::Junk => NameAttribute::Junk,
            NameAttribute::Sent => NameAttribute::Sent,
            NameAttribute::Trash => NameAttribute::Trash,
            // Extensions not supported by this crate
            NameAttribute::Extension(s) => NameAttribute::Extension(to_owned_cow(s)),
        }
    }
}

fn name_attribute(i: &[u8]) -> IResult<&[u8], NameAttribute<'_>> {
    alt((
        // RFC 3501
        value(NameAttribute::NoInferiors, tag_no_case("\\Noinferiors")),
        value(NameAttribute::NoSelect, tag_no_case("\\Noselect")),
        value(NameAttribute::Marked, tag_no_case("\\Marked")),
        value(NameAttribute::Unmarked, tag_no_case("\\Unmarked")),
        // RFC 6154
        value(NameAttribute::All, tag_no_case("\\All")),
        value(NameAttribute::Archive, tag_no_case("\\Archive")),
        value(NameAttribute::Drafts, tag_no_case("\\Drafts")),
        value(NameAttribute::Flagged, tag_no_case("\\Flagged")),
        value(NameAttribute::Junk, tag_no_case("\\Junk")),
        value(NameAttribute::Sent, tag_no_case("\\Sent")),
        value(NameAttribute::Trash, tag_no_case("\\Trash")),
        // Extensions not supported by this crate
        map(
            map_res(
                recognize(pair(tag("\\"), take_while(is_atom_char))),
                from_utf8,
            ),
            |s| NameAttribute::Extension(Cow::Borrowed(s)),
        ),
    ))
    .parse(i)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxListData<'a> {
    pub name_attributes: Vec<NameAttribute<'a>>,
    pub delimiter: Option<Cow<'a, str>>,
    pub name: Cow<'a, str>,
}

impl MailboxListData<'_> {
    pub fn into_owned(self) -> MailboxListData<'static> {
        MailboxListData {
            name_attributes: self
                .name_attributes
                .into_iter()
                .map(|named_attribute| named_attribute.into_owned())
                .collect(),
            delimiter: self.delimiter.map(to_owned_cow),
            name: to_owned_cow(self.name),
        }
    }
}

fn mailbox_list(i: &[u8]) -> IResult<&[u8], MailboxListData<'_>> {
    map(
        (
            parenthesized_list(name_attribute),
            tag(" "),
            alt((map(quoted_utf8, Some), map(nil, |_| None))),
            tag(" "),
            mailbox,
        ),
        |(name_attributes, _, delimiter, _, name)| MailboxListData {
            name_attributes,
            delimiter,
            name,
        },
    )
    .parse(i)
}

fn mailbox_data_list(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(preceded(tag_no_case("LIST "), mailbox_list), |data| {
        MailboxDatum::List(data)
    })
    .parse(i)
}

fn mailbox_data_lsub(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(preceded(tag_no_case("LSUB "), mailbox_list), |data| {
        MailboxDatum::List(data)
    })
    .parse(i)
}

#[derive(Debug, Eq, PartialEq, Clone)]
#[non_exhaustive]
pub enum StatusAttribute {
    HighestModSeq(u64), // RFC 4551
    Messages(u32),
    Recent(u32),
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
}

// Unlike `status_att` in the RFC syntax, this includes the value,
// so that it can return a valid enum object instead of just a key.
fn status_att(i: &[u8]) -> IResult<&[u8], StatusAttribute> {
    alt((
        rfc4551::status_att_val_highest_mod_seq,
        map(
            preceded(tag_no_case("MESSAGES "), number),
            StatusAttribute::Messages,
        ),
        map(
            preceded(tag_no_case("RECENT "), number),
            StatusAttribute::Recent,
        ),
        map(
            preceded(tag_no_case("UIDNEXT "), number),
            StatusAttribute::UidNext,
        ),
        map(
            preceded(tag_no_case("UIDVALIDITY "), number),
            StatusAttribute::UidValidity,
        ),
        map(
            preceded(tag_no_case("UNSEEN "), number),
            StatusAttribute::Unseen,
        ),
    ))
    .parse(i)
}

fn status_att_list(i: &[u8]) -> IResult<&[u8], Vec<StatusAttribute>> {
    // RFC 3501 specifies that the list is non-empty in the formal grammar
    //   status-att-list =  status-att SP number *(SP status-att SP number)
    // but mail.163.com sends an empty list in STATUS response anyway.
    parenthesized_list(status_att).parse(i)
}

fn mailbox_data_status(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(
        (tag_no_case("STATUS "), mailbox, tag(" "), status_att_list),
        |(_, mailbox, _, status)| MailboxDatum::Status { mailbox, status },
    )
    .parse(i)
}

fn mailbox_data_recent(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(
        terminated(number, tag_no_case(" RECENT")),
        MailboxDatum::Recent,
    )
    .parse(i)
}

#[derive(Debug, Eq, PartialEq, Clone)]
#[non_exhaustive]
pub enum MailboxDatum<'a> {
    Exists(u32),
    Flags(Vec<Cow<'a, str>>),
    List(MailboxListData<'a>),
    Search(Vec<u32>),
    Sort(Vec<u32>),
    Status {
        mailbox: Cow<'a, str>,
        status: Vec<StatusAttribute>,
    },
    Recent(u32),
    MetadataSolicited {
        mailbox: Cow<'a, str>,
        values: Vec<Metadata>,
    },
    MetadataUnsolicited {
        mailbox: Cow<'a, str>,
        values: Vec<Cow<'a, str>>,
    },
    GmailLabels(Vec<Cow<'a, str>>),
    GmailMsgId(u64),
    GmailThrId(u64),
}

impl<'a> MailboxDatum<'a> {
    pub fn into_owned(self) -> MailboxDatum<'static> {
        match self {
            MailboxDatum::Exists(seq) => MailboxDatum::Exists(seq),
            MailboxDatum::Flags(flags) => {
                MailboxDatum::Flags(flags.into_iter().map(to_owned_cow).collect())
            }
            MailboxDatum::List(data) => MailboxDatum::List(data.into_owned()),
            MailboxDatum::Search(seqs) => MailboxDatum::Search(seqs),
            MailboxDatum::Sort(seqs) => MailboxDatum::Sort(seqs),
            MailboxDatum::Status { mailbox, status } => MailboxDatum::Status {
                mailbox: to_owned_cow(mailbox),
                status,
            },
            MailboxDatum::Recent(seq) => MailboxDatum::Recent(seq),
            MailboxDatum::MetadataSolicited { mailbox, values } => {
                MailboxDatum::MetadataSolicited {
                    mailbox: to_owned_cow(mailbox),
                    values,
                }
            }
            MailboxDatum::MetadataUnsolicited { mailbox, values } => {
                MailboxDatum::MetadataUnsolicited {
                    mailbox: to_owned_cow(mailbox),
                    values: values.into_iter().map(to_owned_cow).collect(),
                }
            }
            MailboxDatum::GmailLabels(labels) => {
                MailboxDatum::GmailLabels(labels.into_iter().map(to_owned_cow).collect())
            }
            MailboxDatum::GmailMsgId(msgid) => MailboxDatum::GmailMsgId(msgid),
            MailboxDatum::GmailThrId(thrid) => MailboxDatum::GmailThrId(thrid),
        }
    }
}

fn mailbox_data(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    alt((
        mailbox_data_flags,
        mailbox_data_exists,
        mailbox_data_list,
        mailbox_data_lsub,
        mailbox_data_status,
        mailbox_data_recent,
        mailbox_data_search,
        gmail::mailbox_data_gmail_labels,
        gmail::mailbox_data_gmail_msgid,
        gmail::mailbox_data_gmail_thrid,
        rfc5256::mailbox_data_sort,
    ))
    .parse(i)
}

#[derive(Debug, Eq, PartialEq)]
pub struct Address<'a> {
    pub name: Option<Cow<'a, [u8]>>,
    pub adl: Option<Cow<'a, [u8]>>,
    pub mailbox: Option<Cow<'a, [u8]>>,
    pub host: Option<Cow<'a, [u8]>>,
}

impl<'a> Address<'a> {
    pub fn into_owned(self) -> Address<'static> {
        Address {
            name: self.name.map(to_owned_cow),
            adl: self.adl.map(to_owned_cow),
            mailbox: self.mailbox.map(to_owned_cow),
            host: self.host.map(to_owned_cow),
        }
    }
}

// An address structure is a parenthesized list that describes an
// electronic mail address.
fn address(i: &[u8]) -> IResult<&[u8], Address<'_>> {
    paren_delimited(map(
        (
            nstring,
            tag(" "),
            nstring,
            tag(" "),
            nstring,
            tag(" "),
            nstring,
        ),
        |(name, _, adl, _, mailbox, _, host)| Address {
            name: name.map(Cow::Borrowed),
            adl: adl.map(Cow::Borrowed),
            mailbox: mailbox.map(Cow::Borrowed),
            host: host.map(Cow::Borrowed),
        },
    ))
    .parse(i)
}

fn opt_addresses(i: &[u8]) -> IResult<&[u8], Option<Vec<Address<'_>>>> {
    alt((
        map(nil, |_s| None),
        map(
            paren_delimited(many1(terminated(address, opt(char(' '))))),
            Some,
        ),
    ))
    .parse(i)
}

/// An RFC 2822 envelope
///
/// See https://datatracker.ietf.org/doc/html/rfc2822#section-3.6 for more details.
#[derive(Debug, Eq, PartialEq)]
pub struct Envelope<'a> {
    pub date: Option<Cow<'a, [u8]>>,
    pub subject: Option<Cow<'a, [u8]>>,
    /// Author of the message; mailbox responsible for writing the message
    pub from: Option<Vec<Address<'a>>>,
    /// Mailbox of the agent responsible for the message's transmission
    pub sender: Option<Vec<Address<'a>>>,
    /// Mailbox that the author of the message suggests replies be sent to
    pub reply_to: Option<Vec<Address<'a>>>,
    pub to: Option<Vec<Address<'a>>>,
    pub cc: Option<Vec<Address<'a>>>,
    pub bcc: Option<Vec<Address<'a>>>,
    pub in_reply_to: Option<Cow<'a, [u8]>>,
    pub message_id: Option<Cow<'a, [u8]>>,
}

impl<'a> Envelope<'a> {
    pub fn into_owned(self) -> Envelope<'static> {
        Envelope {
            date: self.date.map(to_owned_cow),
            subject: self.subject.map(to_owned_cow),
            from: self
                .from
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            sender: self
                .sender
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            reply_to: self
                .reply_to
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            to: self
                .to
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            cc: self
                .cc
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            bcc: self
                .bcc
                .map(|v| v.into_iter().map(|v| v.into_owned()).collect()),
            in_reply_to: self.in_reply_to.map(to_owned_cow),
            message_id: self.message_id.map(to_owned_cow),
        }
    }
}

// envelope        = "(" env-date SP env-subject SP env-from SP
//                   env-sender SP env-reply-to SP env-to SP env-cc SP
//                   env-bcc SP env-in-reply-to SP env-message-id ")"
//
// env-bcc         = "(" 1*address ")" / nil
//
// env-cc          = "(" 1*address ")" / nil
//
// env-date        = nstring
//
// env-from        = "(" 1*address ")" / nil
//
// env-in-reply-to = nstring
//
// env-message-id  = nstring
//
// env-reply-to    = "(" 1*address ")" / nil
//
// env-sender      = "(" 1*address ")" / nil
//
// env-subject     = nstring
//
// env-to          = "(" 1*address ")" / nil
pub(crate) fn envelope(i: &[u8]) -> IResult<&[u8], Envelope<'_>> {
    paren_delimited(map(
        (
            nstring,
            tag(" "),
            nstring,
            tag(" "),
            opt_addresses,
            tag(" "),
            opt_addresses,
            tag(" "),
            opt_addresses,
            tag(" "),
            opt_addresses,
            tag(" "),
            opt_addresses,
            tag(" "),
            opt_addresses,
            tag(" "),
            nstring,
            tag(" "),
            nstring,
        ),
        |(
            date,
            _,
            subject,
            _,
            from,
            _,
            sender,
            _,
            reply_to,
            _,
            to,
            _,
            cc,
            _,
            bcc,
            _,
            in_reply_to,
            _,
            message_id,
        )| Envelope {
            date: date.map(Cow::Borrowed),
            subject: subject.map(Cow::Borrowed),
            from,
            sender,
            reply_to,
            to,
            cc,
            bcc,
            in_reply_to: in_reply_to.map(Cow::Borrowed),
            message_id: message_id.map(Cow::Borrowed),
        },
    ))
    .parse(i)
}

fn msg_att_envelope(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(preceded(tag_no_case("ENVELOPE "), envelope), |envelope| {
        AttributeValue::Envelope(Box::new(envelope))
    })
    .parse(i)
}

fn msg_att_internal_date(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(
        preceded(tag_no_case("INTERNALDATE "), nstring_utf8),
        |date| AttributeValue::InternalDate(date.unwrap()),
    )
    .parse(i)
}

fn msg_att_flags(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(
        preceded(tag_no_case("FLAGS "), flag_list),
        AttributeValue::Flags,
    )
    .parse(i)
}

fn msg_att_rfc822(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(preceded(tag_no_case("RFC822 "), nstring), |v| {
        AttributeValue::Rfc822(v.map(Cow::Borrowed))
    })
    .parse(i)
}

fn msg_att_rfc822_header(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    // extra space workaround for DavMail
    map(
        (tag_no_case("RFC822.HEADER "), opt(tag(" ")), nstring),
        |(_, _, raw)| AttributeValue::Rfc822Header(raw.map(Cow::Borrowed)),
    )
    .parse(i)
}

fn msg_att_rfc822_size(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(
        preceded(tag_no_case("RFC822.SIZE "), number),
        AttributeValue::Rfc822Size,
    )
    .parse(i)
}

fn msg_att_rfc822_text(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(preceded(tag_no_case("RFC822.TEXT "), nstring), |v| {
        AttributeValue::Rfc822Text(v.map(Cow::Borrowed))
    })
    .parse(i)
}

fn msg_att_uid(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(preceded(tag_no_case("UID "), number), AttributeValue::Uid).parse(i)
}

// msg-att         = "(" (msg-att-dynamic / msg-att-static)
//                    *(SP (msg-att-dynamic / msg-att-static)) ")"
//
// msg-att-dynamic = "FLAGS" SP "(" [flag-fetch *(SP flag-fetch)] ")"
//                     ; MAY change for a message
//
// msg-att-static  = "ENVELOPE" SP envelope / "INTERNALDATE" SP date-time /
//                   "RFC822" [".HEADER" / ".TEXT"] SP nstring /
//                   "RFC822.SIZE" SP number /
//                   "BODY" ["STRUCTURE"] SP body /
//                   "BODY" section ["<" number ">"] SP nstring /
//                   "UID" SP uniqueid
//                     ; MUST NOT change for a message

// RFC 8474 §5.1 — EMAILID
//   "EMAILID" SP "(" objectid ")"
// objectid = 1*ASTRING-CHAR (RFC 8474 §3).  EMAILID is non-optional: a
// compliant server MUST be able to provide one for any stored message,
// so the wire form `EMAILID NIL` is not allowed by the RFC.  If a
// non-compliant server emits it anyway, this parser fails and the
// catch-all `msg_att_unknown` below absorbs the attribute.
fn msg_att_emailid(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(
        preceded(
            tag_no_case("EMAILID "),
            paren_delimited(map_res(take_while1(is_astring_char), from_utf8)),
        ),
        |id| AttributeValue::EmailId(Cow::Borrowed(id)),
    )
    .parse(i)
}

// RFC 8474 §5.2 — THREADID
//   "THREADID" SP ( "(" objectid ")" / nil )
// THREADID may be NIL, which the RFC mandates for messages that do not
// currently have a thread association.  We map NIL → `None`.
fn msg_att_threadid(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(
        preceded(
            tag_no_case("THREADID "),
            alt((
                map(nil, |_| None),
                map(
                    paren_delimited(map_res(take_while1(is_astring_char), from_utf8)),
                    |id| Some(Cow::Borrowed(id)),
                ),
            )),
        ),
        AttributeValue::ThreadId,
    )
    .parse(i)
}

// Catch-all for RFC extension attributes not explicitly handled above.
//
// RFC-compliant servers (Apache James, Stalwart, Dovecot) may include
// attributes from extensions that post-date this crate, for example:
//   - RFC 8514 §2 SAVEDATE
//   - any future extension this crate has not yet typed
//
// When all known parsers fail, this function consumes "name SP value" where
// the value is one of:
//   - a single-level parenthesised group `(...)`
//   - an nstring (NIL / quoted-string / literal) — covers SAVEDATE and NIL forms
//   - a bare atom or number — fallback for any remaining scalar value
//
// The name and value are discarded and `AttributeValue::Unknown` is returned so
// that the rest of the `FETCH` attribute list can be parsed without error.
// Note: deeply nested parenthesised values (beyond one level) are not handled
// by the bare-paren arm; add a dedicated parser if a specific extension needs them.
fn msg_att_unknown(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(
        pair(
            map_res(take_while1(is_atom_char), from_utf8),
            preceded(
                tag(" "),
                alt((
                    value((), paren_delimited(take_while(|c: u8| c != b')'))),
                    value((), nstring),
                    value((), take_while1(|c: u8| c != b' ' && c != b')')),
                )),
            ),
        ),
        |_| AttributeValue::Unknown,
    )
    .parse(i)
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AttributeValue<'a> {
    BodySection {
        section: Option<SectionPath>,
        index: Option<u32>,
        data: Option<Cow<'a, [u8]>>,
    },
    BodyStructure(BodyStructure<'a>),
    Envelope(Box<Envelope<'a>>),
    Flags(Vec<Cow<'a, str>>),
    InternalDate(Cow<'a, str>),
    ModSeq(u64), // RFC 4551, section 3.3.2
    Rfc822(Option<Cow<'a, [u8]>>),
    Rfc822Header(Option<Cow<'a, [u8]>>),
    Rfc822Size(u32),
    Rfc822Text(Option<Cow<'a, [u8]>>),
    Uid(u32),
    /// https://developers.google.com/gmail/imap/imap-extensions#access_to_gmail_labels_x-gm-labels
    GmailLabels(Vec<Cow<'a, str>>),
    GmailMsgId(u64),
    GmailThrId(u64),
    /// RFC 8474 §5.1 — `EMAILID`: a server-assigned unique identifier for
    /// a message. RFC 8474 mandates that the server can always provide an
    /// EMAILID for any stored message, so this variant is non-optional.
    EmailId(Cow<'a, str>),
    /// RFC 8474 §5.2 — `THREADID`: a server-assigned identifier for the
    /// thread a message belongs to.  `None` corresponds to the wire-form
    /// `THREADID NIL`, which RFC 8474 §5.2 mandates for messages that do
    /// not currently have a thread association.
    ThreadId(Option<Cow<'a, str>>),
    /// An unknown or not-yet-supported FETCH attribute.
    ///
    /// Returned for any `msg-att` token that the parser does not explicitly
    /// recognise (e.g. `SAVEDATE` from RFC 8514, or any future extension).
    /// The name and raw value are consumed and discarded so that the rest
    /// of the `FETCH` attribute list can be parsed without error.  Callers
    /// that need the raw value should match on the specific RFC extension
    /// and open a tracking issue or PR.
    Unknown,
}

impl<'a> AttributeValue<'a> {
    pub fn into_owned(self) -> AttributeValue<'static> {
        match self {
            AttributeValue::BodySection {
                section,
                index,
                data,
            } => AttributeValue::BodySection {
                section,
                index,
                data: data.map(to_owned_cow),
            },
            AttributeValue::BodyStructure(body) => AttributeValue::BodyStructure(body.into_owned()),
            AttributeValue::Envelope(e) => AttributeValue::Envelope(Box::new(e.into_owned())),
            AttributeValue::Flags(v) => {
                AttributeValue::Flags(v.into_iter().map(to_owned_cow).collect())
            }
            AttributeValue::InternalDate(v) => AttributeValue::InternalDate(to_owned_cow(v)),
            AttributeValue::ModSeq(v) => AttributeValue::ModSeq(v),
            AttributeValue::Rfc822(v) => AttributeValue::Rfc822(v.map(to_owned_cow)),
            AttributeValue::Rfc822Header(v) => AttributeValue::Rfc822Header(v.map(to_owned_cow)),
            AttributeValue::Rfc822Size(v) => AttributeValue::Rfc822Size(v),
            AttributeValue::Rfc822Text(v) => AttributeValue::Rfc822Text(v.map(to_owned_cow)),
            AttributeValue::Uid(v) => AttributeValue::Uid(v),
            AttributeValue::GmailLabels(v) => {
                AttributeValue::GmailLabels(v.into_iter().map(to_owned_cow).collect())
            }
            AttributeValue::GmailMsgId(v) => AttributeValue::GmailMsgId(v),
            AttributeValue::GmailThrId(v) => AttributeValue::GmailThrId(v),
            AttributeValue::EmailId(v) => AttributeValue::EmailId(to_owned_cow(v)),
            AttributeValue::ThreadId(v) => AttributeValue::ThreadId(v.map(to_owned_cow)),
            AttributeValue::Unknown => AttributeValue::Unknown,
        }
    }
}

fn msg_att(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    alt((
        msg_att_body_section,
        msg_att_body_structure,
        msg_att_envelope,
        msg_att_internal_date,
        msg_att_flags,
        rfc4551::msg_att_mod_seq,
        msg_att_rfc822,
        msg_att_rfc822_header,
        msg_att_rfc822_size,
        msg_att_rfc822_text,
        msg_att_uid,
        gmail::msg_att_gmail_labels,
        gmail::msg_att_gmail_msgid,
        gmail::msg_att_gmail_thrid,
        msg_att_emailid,
        msg_att_threadid,
        msg_att_unknown,
    ))
    .parse(i)
}

fn msg_att_list(i: &[u8]) -> IResult<&[u8], Vec<AttributeValue<'_>>> {
    parenthesized_nonempty_list(msg_att).parse(i)
}

// message-data    = nz-number SP ("EXPUNGE" / ("FETCH" SP msg-att))
fn message_data_fetch(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    map(
        (number, tag_no_case(" FETCH "), msg_att_list),
        |(num, _, attrs)| Response::Fetch(num, attrs),
    )
    .parse(i)
}

// message-data    = nz-number SP ("EXPUNGE" / ("FETCH" SP msg-att))
fn message_data_expunge(i: &[u8]) -> IResult<&[u8], u32> {
    terminated(number, tag_no_case(" EXPUNGE")).parse(i)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestId(pub String);

impl RequestId {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

// tag             = 1*<any ASTRING-CHAR except "+">
fn imap_tag(i: &[u8]) -> IResult<&[u8], RequestId> {
    map(map_res(take_while1(is_tag_char), from_utf8), |s| {
        RequestId(s.to_string())
    })
    .parse(i)
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Outcome<'a> {
    pub code: Option<ResponseCode<'a>>,
    pub information: Option<Cow<'a, str>>,
}

impl Outcome<'_> {
    pub fn into_owned(self) -> Outcome<'static> {
        Outcome {
            code: self.code.map(ResponseCode::into_owned),
            information: self.information.map(to_owned_cow),
        }
    }
}

// This is not quite according to spec, which mandates the following:
//     ["[" resp-text-code "]" SP] text
// However, examples in RFC 4551 (Conditional STORE) counteract this by giving
// examples of `resp-text` that do not include the trailing space and text.
fn resp_text(i: &[u8]) -> IResult<&[u8], Outcome<'_>> {
    map((opt(resp_text_code), text), |(code, text)| {
        let information = if text.is_empty() {
            None
        } else if code.is_some() {
            Some(match text {
                Cow::Borrowed(s) => Cow::Borrowed(&s[1..]),
                Cow::Owned(s) => Cow::Owned(s[1..].to_string()),
            })
        } else {
            Some(text)
        };

        Outcome { code, information }
    })
    .parse(i)
}

// an response-text if it is at the end of a response. Empty text is then allowed without the normally needed trailing space.
fn trailing_resp_text(i: &[u8]) -> IResult<&[u8], Outcome<'_>> {
    map(opt((tag(" "), resp_text)), |resptext| {
        resptext.map(|(_, tuple)| tuple).unwrap_or_default()
    })
    .parse(i)
}

// continue-req    = "+" SP (resp-text / base64) CRLF
pub(crate) fn continue_req(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    // Some servers do not send the space :/
    // TODO: base64
    map(
        (tag("+"), opt(tag(" ")), resp_text, tag("\r\n")),
        |(_, _, outcome, _)| Response::Continue(outcome),
    )
    .parse(i)
}

// response-tagged = tag SP resp-cond-state CRLF
//
// resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text
//                     ; Status condition
pub(crate) fn response_tagged(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    map(
        (imap_tag, tag(" "), status, trailing_resp_text, tag("\r\n")),
        |(tag, _, status, outcome, _)| Response::Done {
            tag,
            status,
            outcome,
        },
    )
    .parse(i)
}

// resp-cond-auth  = ("OK" / "PREAUTH") SP resp-text
//                     ; Authentication condition
//
// resp-cond-bye   = "BYE" SP resp-text
//
// resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text
//                     ; Status condition
fn resp_cond(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    map((status, trailing_resp_text), |(status, outcome)| {
        Response::Data { status, outcome }
    })
    .parse(i)
}

// response-data   = "*" SP (resp-cond-state / resp-cond-bye /
//                   mailbox-data / message-data / capability-data / quota) CRLF
pub(crate) fn response_data(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    delimited(
        tag("* "),
        alt((
            resp_cond,
            map(mailbox_data, Response::MailboxData),
            map(message_data_expunge, Response::Expunge),
            message_data_fetch,
            map(capability_data, Response::Capabilities),
            rfc5161::resp_enabled,
            rfc5464::metadata_solicited,
            rfc5464::metadata_unsolicited,
            rfc7162::resp_vanished,
            rfc2087::quota,
            rfc2087::quota_root,
            rfc2971::resp_id,
            rfc4314::acl,
            rfc4314::list_rights,
            rfc4314::my_rights,
        )),
        preceded(
            many0(tag(" ")), // Outlook server sometimes sends whitespace at the end of STATUS response.
            tag("\r\n"),
        ),
    )
    .parse(i)
}

#[cfg(test)]
mod tests {
    use super::{AttributeValue, Capability, NameAttribute};
    use assert_matches::assert_matches;
    use std::borrow::Cow;

    #[test]
    fn test_list() {
        match super::mailbox(b"iNboX ") {
            Ok((_, mb)) => {
                assert_eq!(mb, "INBOX");
            }
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_envelope() {
        let env = br#"ENVELOPE ("Wed, 17 Jul 1996 02:23:25 -0700 (PDT)" "IMAP4rev1 WG mtg summary and minutes" (("Terry Gray" NIL "gray" "cac.washington.edu")) (("Terry Gray" NIL "gray" "cac.washington.edu")) (("Terry Gray" NIL "gray" "cac.washington.edu")) ((NIL NIL "imap" "cac.washington.edu")) ((NIL NIL "minutes" "CNRI.Reston.VA.US") ("John Klensin" NIL "KLENSIN" "MIT.EDU")) NIL NIL "<B27397-0100000@cac.washington.edu>") "#;
        match super::msg_att_envelope(env) {
            Ok((_, AttributeValue::Envelope(_))) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_opt_addresses() {
        let addr = b"((NIL NIL \"minutes\" \"CNRI.Reston.VA.US\") (\"John Klensin\" NIL \"KLENSIN\" \"MIT.EDU\")) ";
        match super::opt_addresses(addr) {
            Ok((_, _addresses)) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_opt_addresses_no_space() {
        let addr =
            br#"((NIL NIL "test" "example@example.com")(NIL NIL "test" "example@example.com"))"#;
        match super::opt_addresses(addr) {
            Ok((_, _addresses)) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_addresses() {
        match super::address(b"(\"John Klensin\" NIL \"KLENSIN\" \"MIT.EDU\") ") {
            Ok((_, _address)) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }

        // Literal non-UTF8 address
        match super::address(b"({12}\r\nJoh\xff Klensin NIL \"KLENSIN\" \"MIT.EDU\") ") {
            Ok((_, _address)) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_capability_data() {
        // Minimal capabilities
        assert_matches!(
            super::capability_data(b"CAPABILITY IMAP4rev1\r\n"),
            Ok((_, capabilities)) => {
                assert_eq!(capabilities, vec![Capability::Imap4rev1])
            }
        );

        assert_matches!(
            super::capability_data(b"CAPABILITY XPIG-LATIN IMAP4rev1 STARTTLS AUTH=GSSAPI\r\n"),
            Ok((_, capabilities)) => {
                assert_eq!(capabilities, vec![
                    Capability::Atom(Cow::Borrowed("XPIG-LATIN")),
                    Capability::Imap4rev1,
                    Capability::Atom(Cow::Borrowed("STARTTLS")),
                    Capability::Auth(Cow::Borrowed("GSSAPI")),
                ])
            }
        );

        assert_matches!(
            super::capability_data(b"CAPABILITY IMAP4rev1 AUTH=GSSAPI AUTH=PLAIN\r\n"),
            Ok((_, capabilities)) => {
                assert_eq!(capabilities, vec![
                    Capability::Imap4rev1,
                    Capability::Auth(Cow::Borrowed("GSSAPI")),
                    Capability::Auth(Cow::Borrowed("PLAIN")),
                ])
            }
        );

        // Capability command must contain IMAP4rev1
        assert_matches!(
            super::capability_data(b"CAPABILITY AUTH=GSSAPI AUTH=PLAIN\r\n"),
            Err(_)
        );
    }

    #[test]
    fn test_surgemail_select_flags() {
        // Tests workaround for surgemail with space before closing bracket
        assert_matches!(
            super::flag_list(b"(\\Answered \\Flagged \\Deleted \\Draft \\Seen $Forwarded )"),
            Ok(([], flags)) => {
                assert_eq!(flags, vec![
                        "\\Answered",
                        "\\Flagged",
                        "\\Deleted",
                        "\\Draft",
                        "\\Seen",
                        "$Forwarded"
                    ])
            }
        );
    }

    /// Tests that the [`NameAttribute::into_owned`] method returns the
    /// same value (the ownership should only change).
    #[test]
    fn test_name_attribute_into_owned() {
        let name_attributes = [
            // RFC 3501
            NameAttribute::NoInferiors,
            NameAttribute::NoSelect,
            NameAttribute::Marked,
            NameAttribute::Unmarked,
            // RFC 6154
            NameAttribute::All,
            NameAttribute::Archive,
            NameAttribute::Drafts,
            NameAttribute::Flagged,
            NameAttribute::Junk,
            NameAttribute::Sent,
            NameAttribute::Trash,
            // Extensions not supported by this crate
            NameAttribute::Extension(Cow::Borrowed("Foobar")),
        ];

        for name_attribute in name_attributes {
            let owned_name_attribute = name_attribute.clone().into_owned();
            assert_eq!(name_attribute, owned_name_attribute);
        }
    }

    #[test]
    fn test_attribute_value_unknown_into_owned() {
        assert_eq!(
            AttributeValue::Unknown.into_owned(),
            AttributeValue::Unknown
        );
    }
}
