// rustfmt doesn't do a very good job on nom parser invocations.
#![cfg_attr(rustfmt, rustfmt_skip)]
#![cfg_attr(feature = "cargo-clippy", allow(redundant_closure))]

use nom::{self, IResult};

use std::str;

use types::*;


fn crlf(c: u8) -> bool {
    c == b'\r' || c == b'\n'
}

fn list_wildcards(c: u8) -> bool {
    c == b'%' || c == b'*'
}

fn quoted_specials(c: u8) -> bool {
    c == b'"' || c == b'\\'
}

fn resp_specials(c: u8) -> bool {
    c == b']'
}

fn atom_specials(c: u8) -> bool {
    c == b'(' || c == b')' || c == b'{' || c == b' ' || c < 32 || list_wildcards(c)
        || quoted_specials(c) || resp_specials(c)
}

fn atom_char(c: u8) -> bool {
    !atom_specials(c)
}

fn astring_char(c: u8) -> bool {
    atom_char(c) || resp_specials(c)
}

fn tag_char(c: u8) -> bool {
    c != b'+' && astring_char(c)
}

// Ideally this should use nom's `escaped` macro, but it suffers from broken
// type inference unless compiled with the verbose-errors feature enabled.
fn quoted_data(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let mut escape = false;
    let mut len = 0;
    for c in i {
        if *c == b'"' && !escape {
            break;
        }
        len += 1;
        if *c == b'\\' && !escape {
            escape = true
        } else if escape {
            escape = false;
        }
    }
    IResult::Done(&i[len..], &i[..len])
}

named!(quoted<&[u8]>, do_parse!(
    tag_s!("\"") >>
    data: quoted_data >>
    tag_s!("\"") >>
    (data)
));

named!(literal<&[u8]>, do_parse!(
    tag_s!("{") >>
    len: number >>
    tag_s!("}") >>
    tag_s!("\r\n") >>
    data: take!(len) >>
    (data)
));

named!(string<&[u8]>, alt!(quoted | literal));

named!(status_ok<Status>, map!(tag_no_case!("OK"),
    |s| Status::Ok
));
named!(status_no<Status>, map!(tag_no_case!("NO"),
    |s| Status::No
));
named!(status_bad<Status>, map!(tag_no_case!("BAD"),
    |s| Status::Bad
));
named!(status_preauth<Status>, map!(tag_no_case!("PREAUTH"),
    |s| Status::PreAuth
));
named!(status_bye<Status>, map!(tag_no_case!("BYE"),
    |s| Status::Bye
));

named!(status<Status>, alt!(
    status_ok |
    status_no |
    status_bad |
    status_preauth |
    status_bye
));

named!(number<u32>, map_res!(
    map_res!(nom::digit, str::from_utf8),
    str::parse
));

named!(number_64<u64>, map_res!(
    map_res!(nom::digit, str::from_utf8),
    str::parse
));

named!(text<&str>, map_res!(take_till_s!(crlf),
    str::from_utf8
));

named!(atom<&str>, map_res!(take_while1_s!(atom_char),
    str::from_utf8
));

named!(astring<&[u8]>, alt!(
    take_while1_s!(astring_char) |
    string
));

named!(mailbox<&str>, alt!(
    map!(tag_s!("INBOX"), |s| "INBOX") |
    map_res!(astring, str::from_utf8)
));

named!(flag_extension<&str>, map_res!(
    recognize!(pair!(tag!("\\"), take_while!(atom_char))),
    str::from_utf8
));

named!(flag<&str>, alt!(flag_extension | atom));

named!(flag_list<Vec<&str>>, do_parse!(
    tag_s!("(") >>
    elements: opt!(do_parse!(
        flag0: flag >>
        flags: many0!(do_parse!(
            tag_s!(" ") >>
            flag: flag >>
            (flag)
        )) >> ({
            let mut res = vec![flag0];
            res.extend(flags);
            res
        })
    )) >>
    tag_s!(")") >> ({
       if elements.is_some() {
           elements.unwrap()
       } else {
           Vec::new()
       }
    })
));

named!(flag_perm<&str>, alt!(
    map_res!(tag_s!("\\*"), str::from_utf8) |
    flag
));

named!(section_part<Vec<u32>>, do_parse!(
    part: number >>
    rest: many0!(do_parse!(
        tag_s!(".") >>
        part: number >>
        (part)
    ))  >> ({
        let mut res = vec![part];
        res.extend(rest);
        res
    })
));

named!(section_msgtext<MessageSection>, map!(
    alt!(tag_s!("HEADER") | tag_s!("TEXT")),
    |s| match s {
        b"HEADER" => MessageSection::Header,
        b"TEXT" => MessageSection::Text,
        _ => panic!("cannot happen"),
    }
));

named!(section_text<MessageSection>, alt!(
    section_msgtext |
    do_parse!(tag_s!("MIME") >> (MessageSection::Mime))
));

named!(section_spec<SectionPath>, alt!(
    map!(section_msgtext, |val| SectionPath::Full(val)) |
    do_parse!(
        part: section_part >>
        text: opt!(do_parse!(
            tag_s!(".") >>
            text: section_text >>
            (text)
        )) >>
        (SectionPath::Part(part, text))
    )
));

named!(section<Option<SectionPath>>, do_parse!(
    tag_s!("[") >>
    spec: opt!(section_spec) >>
    tag_s!("]") >>
    (spec)
));

named!(resp_text_code_permanent_flags<ResponseCode>, do_parse!(
    tag_s!("PERMANENTFLAGS (") >>
    elements: opt!(do_parse!(
        flag0: flag_perm >>
        flags: many0!(do_parse!(
            tag_s!(" ") >>
            flag: flag_perm >>
            (flag)
        )) >> ({
            let mut res = vec![flag0];
            res.extend(flags);
            res
        })
    )) >>
    tag_s!(")") >> ({
        ResponseCode::PermanentFlags(if elements.is_some() {
            elements.unwrap()
        } else {
            Vec::new()
        })
    })
));

named!(resp_text_code_highest_mod_seq<ResponseCode>, do_parse!(
    tag_s!("HIGHESTMODSEQ ") >>
    num: number_64 >>
    (ResponseCode::HighestModSeq(num))
));

named!(resp_text_code_read_only<ResponseCode>, do_parse!(
    tag_s!("READ-ONLY") >>
    (ResponseCode::ReadOnly)
));

named!(resp_text_code_read_write<ResponseCode>, do_parse!(
    tag_s!("READ-WRITE") >>
    (ResponseCode::ReadWrite)
));

named!(resp_text_code_try_create<ResponseCode>, do_parse!(
    tag_s!("TRYCREATE") >>
    (ResponseCode::TryCreate)
));

named!(resp_text_code_uid_validity<ResponseCode>, do_parse!(
    tag_s!("UIDVALIDITY ") >>
    num: number >>
    (ResponseCode::UidValidity(num))
));

named!(resp_text_code_uid_next<ResponseCode>, do_parse!(
    tag_s!("UIDNEXT ") >>
    num: number >>
    (ResponseCode::UidNext(num))
));

named!(resp_text_code_unseen<ResponseCode>, do_parse!(
    tag_s!("UNSEEN ") >>
    num: number >>
    (ResponseCode::Unseen(num))
));

named!(resp_text_code<ResponseCode>, do_parse!(
    tag_s!("[") >>
    coded: alt!(
        resp_text_code_permanent_flags |
        resp_text_code_uid_validity |
        resp_text_code_uid_next |
        resp_text_code_unseen |
        resp_text_code_read_only |
        resp_text_code_read_write |
        resp_text_code_try_create |
        resp_text_code_highest_mod_seq
    ) >>
    // Per the spec, the closing tag should be "] ".
    // See `resp_text` for more on why this is done differently.
    tag_s!("]") >>
    (coded)
));

named!(capability<&str>, do_parse!(
    tag_s!(" ") >>
    atom: map_res!(take_till1_s!(atom_specials), str::from_utf8) >>
    (atom)
));

named!(capability_data<Response>, do_parse!(
    tag_s!("CAPABILITY") >>
    capabilities: many1!(capability) >>
    (Response::Capabilities(capabilities))
));

named!(mailbox_data_flags<Response>, do_parse!(
    tag_s!("FLAGS ") >>
    flags: flag_list >>
    (Response::MailboxData(MailboxDatum::Flags(flags)))
));

named!(mailbox_data_exists<Response>, do_parse!(
    num: number >>
    tag_s!(" EXISTS") >>
    (Response::MailboxData(MailboxDatum::Exists(num)))
));

named!(mailbox_data_list<Response>, do_parse!(
    tag_s!("LIST ") >>
    flags: flag_list >>
    tag_s!(" ") >>
    delimiter: map_res!(quoted, str::from_utf8) >>
    tag_s!(" ") >>
    name: mailbox >>
    (Response::MailboxData(MailboxDatum::List {
        flags,
        delimiter,
        name
    }))
));

named!(mailbox_data_lsub<Response>, do_parse!(
    tag_s!("LSUB ") >>
    flags: flag_list >>
    tag_s!(" ") >>
    delimiter: map_res!(quoted, str::from_utf8) >>
    tag_s!(" ") >>
    name: mailbox >>
    (Response::MailboxData(MailboxDatum::SubList {
        flags,
        delimiter,
        name
    }))
));

// Unlike `status_att` in the RFC syntax, this includes the value,
// so that it can return a valid enum object instead of just a key.
named!(status_att<StatusAttribute>, do_parse!(
    key: alt!(
        tag_s!("MESSAGES") |
        tag_s!("RECENT") |
        tag_s!("UIDNEXT") |
        tag_s!("UIDVALIDITY") |
        tag_s!("UNSEEN")
    ) >>
    tag_s!(" ") >>
    val: number >>
    (match key {
        b"MESSAGES" => StatusAttribute::Messages(val),
        b"RECENT" => StatusAttribute::Recent(val),
        b"UIDNEXT" => StatusAttribute::UidNext(val),
        b"UIDVALIDITY" => StatusAttribute::UidValidity(val),
        b"UNSEEN" => StatusAttribute::Unseen(val),
        _ => panic!("invalid status key {}", str::from_utf8(key).unwrap()),
    })
));

named!(status_att_list<Vec<StatusAttribute>>, do_parse!(
    first: status_att >>
    rest: many0!(do_parse!(
        tag_s!(" ") >>
        status: status_att >>
        (status)
    )) >>
    ({
        let mut res = rest;
        res.insert(0, first);
        res
    })
));

named!(mailbox_data_status<Response>, do_parse!(
    tag_s!("STATUS ") >>
    mailbox: mailbox >>
    tag_s!(" (") >>
    status: status_att_list >>
    tag_s!(")") >>
    (Response::MailboxData(MailboxDatum::Status {
        mailbox,
        status,
    }))
));

named!(mailbox_data_recent<Response>, do_parse!(
    num: number >>
    tag_s!(" RECENT") >>
    (Response::MailboxData(MailboxDatum::Recent(num)))
));

named!(mailbox_data<Response>, alt!(
    mailbox_data_flags |
    mailbox_data_exists |
    mailbox_data_list |
    mailbox_data_lsub |
    mailbox_data_status |
    mailbox_data_recent
));

named!(nstring<Option<&[u8]>>, map!(
    alt!(tag_s!("NIL") | string),
    |s| if s == b"NIL" { None } else { Some(s) }
));

named!(address<Address>, do_parse!(
    tag_s!("(") >>
    name: nstring >>
    tag_s!(" ") >>
    adl: nstring >>
    tag_s!(" ") >>
    mailbox: nstring >>
    tag_s!(" ") >>
    host: nstring >>
    tag_s!(")") >>
    (Address {
        name: name.map(|s| str::from_utf8(s).unwrap()),
        adl: adl.map(|s| str::from_utf8(s).unwrap()),
        mailbox: mailbox.map(|s| str::from_utf8(s).unwrap()),
        host: host.map(|s| str::from_utf8(s).unwrap()),
    })
));

named!(opt_addresses<Option<Vec<Address>>>, alt!(
    map!(tag_s!("NIL"), |s| None) |
    do_parse!(
        tag_s!("(") >>
        addrs: many1!(address) >>
        tag_s!(")") >>
        (Some(addrs))
    )
));

named!(msg_att_body_section<AttributeValue>, do_parse!(
    tag_s!("BODY") >>
    section: section >>
    index: opt!(do_parse!(
        tag_s!("<") >>
        num: number >>
        tag_s!(">") >>
        (num)
    )) >>
    tag_s!(" ") >>
    data: nstring >>
    (AttributeValue::BodySection { section, index, data })
));

named!(msg_att_envelope<AttributeValue>, do_parse!(
    tag_s!("ENVELOPE (") >>
    date: nstring >>
    tag_s!(" ") >>
    subject: nstring >>
    tag_s!(" ") >>
    from: opt_addresses >>
    tag_s!(" ") >>
    sender: opt_addresses >>
    tag_s!(" ") >>
    reply_to: opt_addresses >>
    tag_s!(" ") >>
    to: opt_addresses >>
    tag_s!(" ") >>
    cc: opt_addresses >>
    tag_s!(" ") >>
    bcc: opt_addresses >>
    tag_s!(" ") >>
    in_reply_to: nstring >>
    tag_s!(" ") >>
    message_id: nstring >>
    tag_s!(")") >> ({
        AttributeValue::Envelope(Envelope {
            date: date.map(|s| str::from_utf8(s).unwrap()),
            subject: subject.map(|s| str::from_utf8(s).unwrap()),
            from,
            sender,
            reply_to,
            to,
            cc,
            bcc,
            in_reply_to: in_reply_to.map(|s| str::from_utf8(s).unwrap()),
            message_id: message_id.map(|s| str::from_utf8(s).unwrap()),
        })
    })
));

named!(msg_att_internal_date<AttributeValue>, do_parse!(
    tag_s!("INTERNALDATE ") >>
    date: nstring >>
    (AttributeValue::InternalDate(str::from_utf8(date.unwrap()).unwrap()))
));

named!(msg_att_flags<AttributeValue>, do_parse!(
    tag_s!("FLAGS ") >>
    flags: flag_list >>
    (AttributeValue::Flags(flags))
));

named!(msg_att_rfc822<AttributeValue>, do_parse!(
    tag_s!("RFC822 ") >>
    raw: nstring >>
    (AttributeValue::Rfc822(raw))
));

named!(msg_att_rfc822_size<AttributeValue>, do_parse!(
    tag_s!("RFC822.SIZE ") >>
    num: number >>
    (AttributeValue::Rfc822Size(num))
));

named!(msg_att_mod_seq<AttributeValue>, do_parse!(
    tag_s!("MODSEQ (") >>
    num: number_64 >>
    tag_s!(")") >>
    (AttributeValue::ModSeq(num))
));

named!(msg_att_uid<AttributeValue>, do_parse!(
    tag_s!("UID ") >>
    num: number >>
    (AttributeValue::Uid(num))
));

named!(msg_att<AttributeValue>, alt!(
    msg_att_body_section |
    msg_att_envelope |
    msg_att_internal_date |
    msg_att_flags |
    msg_att_mod_seq |
    msg_att_rfc822 |
    msg_att_rfc822_size |
    msg_att_uid
));

named!(msg_att_list<Vec<AttributeValue>>, do_parse!(
    tag_s!("(") >>
    elements: do_parse!(
        attr0: msg_att >>
        attrs: many0!(do_parse!(
            tag_s!(" ") >>
            attr: msg_att >>
            (attr)
        )) >> ({
            let mut res = vec![attr0];
            res.extend(attrs);
            res
        })
    ) >>
    tag_s!(")") >>
    (elements)
));

named!(message_data_fetch<Response>, do_parse!(
    num: number >>
    tag_s!(" FETCH ") >>
    attrs: msg_att_list >>
    (Response::Fetch(num, attrs))
));

named!(message_data_expunge<Response>, do_parse!(
    num: number >>
    tag_s!(" EXPUNGE") >>
    (Response::Expunge(num))
));

named!(tag<RequestId>, map!(
    map_res!(take_while1_s!(tag_char), str::from_utf8),
    |s| RequestId(s.to_string())
));

// This is not quite according to spec, which mandates the following:
//     ["[" resp-text-code "]" SP] text
// However, examples in RFC 4551 (Conditional STORE) counteract this by giving
// examples of `resp-text` that do not include the trailing space and text.
named!(resp_text<(Option<ResponseCode>, Option<&str>)>, do_parse!(
    code: opt!(resp_text_code) >>
    text: text >>
    ({
        let res = if text.len() < 1 {
            None
        } else if code.is_some() {
            Some(&text[1..])
        } else {
            Some(text)
        };
        (code, res)
    })
));

named!(response_tagged<Response>, do_parse!(
    tag: tag >>
    tag_s!(" ") >>
    status: status >>
    tag_s!(" ") >>
    text: resp_text >>
    tag_s!("\r\n") >>
    (Response::Done {
        tag,
        status,
        code: text.0,
        information: text.1,
    })
));

named!(resp_cond<Response>, do_parse!(
    status: status >>
    tag_s!(" ") >>
    text: resp_text >>
    (Response::Data {
        status,
        code: text.0,
        information: text.1,
    })
));

named!(response_data<Response>, do_parse!(
    tag_s!("* ") >>
    contents: alt!(
        resp_cond |
        mailbox_data |
        message_data_expunge |
        message_data_fetch |
        capability_data
    ) >>
    tag_s!("\r\n") >>
    (contents)
));

named!(response<Response>, alt!(
    response_data |
    response_tagged
));

pub type ParseResult<'a> = IResult<&'a [u8], Response<'a>>;

pub fn parse_response(msg: &[u8]) -> ParseResult {
    response(msg)
}


#[cfg(test)]
mod tests {
    use types::*;
    use super::{parse_response, IResult};

    #[test]
    fn test_number_overflow() {
        match parse_response(b"* 2222222222222222222222222222222222222222222C\r\n") {
            IResult::Error(_) => {},
            _ => panic!("error required for integer overflow"),
        }
    }

    #[test]
    fn test_unseen() {
        match parse_response(b"* OK [UNSEEN 3] Message 3 is first unseen\r\n").unwrap() {
            (_, Response::Data {
                status: Status::Ok,
                code: Some(ResponseCode::Unseen(3)),
                information: Some("Message 3 is first unseen"),
            }) => {},
            rsp @ _ => panic!("unexpected response {:?}", rsp),
        }
    }

    #[test]
    fn test_body_text() {
        match parse_response(b"* 2 FETCH (BODY[TEXT] {3}\r\nfoo)\r\n") {
            IResult::Done(_, Response::Fetch(_, attrs)) => {
                let body = &attrs[0];
                assert_eq!(body, &AttributeValue::BodySection {
                    section: Some(SectionPath::Full(MessageSection::Text)),
                    index: None,
                    data: Some(b"foo"),
                }, "body = {:?}", body);
            },
            rsp @ _ => panic!("unexpected response {:?}", rsp),
        }
    }

    #[test]
    fn test_status() {
        match parse_response(b"* STATUS blurdybloop (MESSAGES 231 UIDNEXT 44292)\r\n") {
            IResult::Done(_, Response::MailboxData(MailboxDatum::Status { mailbox, status })) => {
                assert_eq!(mailbox, "blurdybloop");
                assert_eq!(status, [
                    StatusAttribute::Messages(231),
                    StatusAttribute::UidNext(44292),
                ]);
            },
            rsp @ _ => panic!("unexpected response {:?}", rsp),
        }
    }
}
