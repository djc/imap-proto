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

use crate::{
    parser::{
        core::*, rfc2087, rfc2971, rfc3501::body::*, rfc3501::body_structure::*, rfc4314, rfc4315,
        rfc4551, rfc5161, rfc5256, rfc5464, rfc7162,
    },
    types::*,
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

// tag             = 1*<any ASTRING-CHAR except "+">
fn imap_tag(i: &[u8]) -> IResult<&[u8], RequestId> {
    map(map_res(take_while1(is_tag_char), from_utf8), |s| {
        RequestId(s.to_string())
    })
    .parse(i)
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
    use crate::types::*;
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
}
