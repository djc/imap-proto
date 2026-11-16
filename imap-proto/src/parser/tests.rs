use super::{bodystructure::BodyStructParser, parse_response};
use crate::types::*;
use std::borrow::Cow;
use std::num::NonZeroUsize;

#[test]
fn test_mailbox_data_response() {
    match parse_response(b"* LIST (\\HasNoChildren) \".\" INBOX.Tests\r\n") {
        Ok((_, Response::MailboxData(_))) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

/// Test that the name attributes in [RFC 3501 Section 7.2.2](https://datatracker.ietf.org/doc/html/rfc3501#section-7.2.2)
/// and extensions can be parsed.
#[test]
fn test_name_attributes() {
    match parse_response(
        b"* LIST (\\Noinferiors \\Noselect \\Marked \\Unmarked \\All \\Archive \\Drafts \\Flagged \\Junk \\Sent \\Trash \\Foobar) \".\" INBOX.Tests\r\n",
    ) {
        Ok((
            _,
            Response::MailboxData(MailboxDatum::List {
                name_attributes, ..
            }),
        )) => {
            assert_eq!(
                name_attributes,
                vec![
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
                    NameAttribute::Extension(Cow::Borrowed("\\Foobar")),
                ]
            );
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

/// Test the ACL response from RFC 4314/2086
#[test]
fn test_acl_response() {
    match parse_response(b"* ACL INBOX user lrswipkxtecdan\r\n") {
        Ok((_, Response::Acl(_))) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_acl_attributes() {
    // no rights
    match parse_response(b"* ACL INBOX\r\n") {
        Ok((_, Response::Acl(acl))) => {
            assert_eq!(
                acl,
                Acl {
                    mailbox: Cow::Borrowed("INBOX"),
                    acls: vec![],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // one right pair
    match parse_response(b"* ACL INBOX user lrswipkxtecdan\r\n") {
        Ok((_, Response::Acl(acl))) => {
            assert_eq!(
                acl,
                Acl {
                    mailbox: Cow::Borrowed("INBOX"),
                    acls: vec![AclEntry {
                        identifier: Cow::Borrowed("user"),
                        rights: vec![
                            AclRight::Lookup,
                            AclRight::Read,
                            AclRight::Seen,
                            AclRight::Write,
                            AclRight::Insert,
                            AclRight::Post,
                            AclRight::CreateMailbox,
                            AclRight::DeleteMailbox,
                            AclRight::DeleteMessage,
                            AclRight::Expunge,
                            AclRight::OldCreate,
                            AclRight::OldDelete,
                            AclRight::Administer,
                            AclRight::Annotation,
                        ],
                    },],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // with custom rights
    match parse_response(b"* ACL INBOX user lr0123\r\n") {
        Ok((_, Response::Acl(acl))) => {
            assert_eq!(
                acl,
                Acl {
                    mailbox: Cow::Borrowed("INBOX"),
                    acls: vec![AclEntry {
                        identifier: Cow::Borrowed("user"),
                        rights: vec![
                            AclRight::Lookup,
                            AclRight::Read,
                            AclRight::Custom('0'),
                            AclRight::Custom('1'),
                            AclRight::Custom('2'),
                            AclRight::Custom('3'),
                        ],
                    },],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // multiple right pairs
    match parse_response(b"* ACL INBOX user lrswipkxtecdan user2 lr\r\n") {
        Ok((_, Response::Acl(acl))) => {
            assert_eq!(
                acl,
                Acl {
                    mailbox: Cow::Borrowed("INBOX"),
                    acls: vec![
                        AclEntry {
                            identifier: Cow::Borrowed("user"),
                            rights: vec![
                                AclRight::Lookup,
                                AclRight::Read,
                                AclRight::Seen,
                                AclRight::Write,
                                AclRight::Insert,
                                AclRight::Post,
                                AclRight::CreateMailbox,
                                AclRight::DeleteMailbox,
                                AclRight::DeleteMessage,
                                AclRight::Expunge,
                                AclRight::OldCreate,
                                AclRight::OldDelete,
                                AclRight::Administer,
                                AclRight::Annotation,
                            ],
                        },
                        AclEntry {
                            identifier: Cow::Borrowed("user2"),
                            rights: vec![AclRight::Lookup, AclRight::Read],
                        },
                    ],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // quoted mailbox
    match parse_response(b"* ACL \"My folder\" user lrswipkxtecdan\r\n") {
        Ok((_, Response::Acl(acl))) => {
            assert_eq!(
                acl,
                Acl {
                    mailbox: Cow::Borrowed("My folder"),
                    acls: vec![AclEntry {
                        identifier: Cow::Borrowed("user"),
                        rights: vec![
                            AclRight::Lookup,
                            AclRight::Read,
                            AclRight::Seen,
                            AclRight::Write,
                            AclRight::Insert,
                            AclRight::Post,
                            AclRight::CreateMailbox,
                            AclRight::DeleteMailbox,
                            AclRight::DeleteMessage,
                            AclRight::Expunge,
                            AclRight::OldCreate,
                            AclRight::OldDelete,
                            AclRight::Administer,
                            AclRight::Annotation,
                        ],
                    },],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // quoted identifier
    match parse_response(b"* ACL Trash \"user name\" lrswipkxtecdan\r\n") {
        Ok((_, Response::Acl(acl))) => {
            assert_eq!(
                acl,
                Acl {
                    mailbox: Cow::Borrowed("Trash"),
                    acls: vec![AclEntry {
                        identifier: Cow::Borrowed("user name"),
                        rights: vec![
                            AclRight::Lookup,
                            AclRight::Read,
                            AclRight::Seen,
                            AclRight::Write,
                            AclRight::Insert,
                            AclRight::Post,
                            AclRight::CreateMailbox,
                            AclRight::DeleteMailbox,
                            AclRight::DeleteMessage,
                            AclRight::Expunge,
                            AclRight::OldCreate,
                            AclRight::OldDelete,
                            AclRight::Administer,
                            AclRight::Annotation,
                        ],
                    },],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

/// Test the LISTRIGHTS response from RFC 4314/2086
#[test]
fn test_list_rights_response() {
    match parse_response(b"* LISTRIGHTS INBOX user lkxca r s w i p t e d n\r\n") {
        Ok((_, Response::ListRights(_))) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_list_rights_attributes() {
    // no required/always rights, and no optional rights
    match parse_response(b"* LISTRIGHTS INBOX user \"\"\r\n") {
        Ok((_, Response::ListRights(rights))) => {
            assert_eq!(
                rights,
                ListRights {
                    mailbox: Cow::Borrowed("INBOX"),
                    identifier: Cow::Borrowed("user"),
                    required: vec![],
                    optional: vec![],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // no required/always rights, and with optional rights
    match parse_response(b"* LISTRIGHTS INBOX user \"\" l k x c\r\n") {
        Ok((_, Response::ListRights(rights))) => {
            assert_eq!(
                rights,
                ListRights {
                    mailbox: Cow::Borrowed("INBOX"),
                    identifier: Cow::Borrowed("user"),
                    required: vec![],
                    optional: vec![
                        AclRight::Lookup,
                        AclRight::CreateMailbox,
                        AclRight::DeleteMailbox,
                        AclRight::OldCreate,
                    ],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // with required/always rights, and with optional rights
    match parse_response(b"* LISTRIGHTS INBOX user lkr x c\r\n") {
        Ok((_, Response::ListRights(rights))) => {
            assert_eq!(
                rights,
                ListRights {
                    mailbox: Cow::Borrowed("INBOX"),
                    identifier: Cow::Borrowed("user"),
                    required: vec![AclRight::Lookup, AclRight::CreateMailbox, AclRight::Read],
                    optional: vec![AclRight::DeleteMailbox, AclRight::OldCreate],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // with required/always rights, and no optional rights
    match parse_response(b"* LISTRIGHTS INBOX user lkr\r\n") {
        Ok((_, Response::ListRights(rights))) => {
            assert_eq!(
                rights,
                ListRights {
                    mailbox: Cow::Borrowed("INBOX"),
                    identifier: Cow::Borrowed("user"),
                    required: vec![AclRight::Lookup, AclRight::CreateMailbox, AclRight::Read],
                    optional: vec![],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // with mailbox with spaces
    match parse_response(b"* LISTRIGHTS \"My Folder\" user lkr x c\r\n") {
        Ok((_, Response::ListRights(rights))) => {
            assert_eq!(
                rights,
                ListRights {
                    mailbox: Cow::Borrowed("My Folder"),
                    identifier: Cow::Borrowed("user"),
                    required: vec![AclRight::Lookup, AclRight::CreateMailbox, AclRight::Read],
                    optional: vec![AclRight::DeleteMailbox, AclRight::OldCreate],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

/// Test the MYRIGHTS response from RFC 4314/2086
#[test]
fn test_my_rights_response() {
    match parse_response(b"* MYRIGHTS INBOX lkxca\r\n") {
        Ok((_, Response::MyRights(_))) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_my_rights_attributes() {
    // with rights
    match parse_response(b"* MYRIGHTS INBOX lkr\r\n") {
        Ok((_, Response::MyRights(rights))) => {
            assert_eq!(
                rights,
                MyRights {
                    mailbox: Cow::Borrowed("INBOX"),
                    rights: vec![AclRight::Lookup, AclRight::CreateMailbox, AclRight::Read],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // with space in mailbox
    match parse_response(b"* MYRIGHTS \"My Folder\" lkr\r\n") {
        Ok((_, Response::MyRights(rights))) => {
            assert_eq!(
                rights,
                MyRights {
                    mailbox: Cow::Borrowed("My Folder"),
                    rights: vec![AclRight::Lookup, AclRight::CreateMailbox, AclRight::Read],
                }
            )
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_number_overflow() {
    match parse_response(b"* 2222222222222222222222222222222222222222222C\r\n") {
        Err(_) => {}
        _ => panic!("error required for integer overflow"),
    }
}

#[test]
fn test_unseen() {
    match parse_response(b"* OK [UNSEEN 3] Message 3 is first unseen\r\n").unwrap() {
        (
            _,
            Response::Data {
                status: Status::Ok,
                code: Some(ResponseCode::Unseen(3)),
                information: Some(Cow::Borrowed("Message 3 is first unseen")),
            },
        ) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_body_text() {
    match parse_response(b"* 2 FETCH (BODY[TEXT] {3}\r\nfoo)\r\n") {
        Ok((_, Response::Fetch(_, attrs))) => {
            let body = &attrs[0];
            assert_eq!(
                body,
                &AttributeValue::BodySection {
                    section: Some(SectionPath::Full(MessageSection::Text)),
                    index: None,
                    data: Some(Cow::Borrowed(b"foo")),
                },
                "body = {body:?}"
            );
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_body_structure() {
    const RESPONSE: &[u8] = b"* 15 FETCH (BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"iso-8859-1\") NIL NIL \"QUOTED-PRINTABLE\" 1315 42 NIL NIL NIL NIL))\r\n";
    match parse_response(RESPONSE) {
        Ok((_, Response::Fetch(_, attrs))) => {
            let body = &attrs[0];
            assert!(
                matches!(*body, AttributeValue::BodyStructure(_)),
                "body = {body:?}"
            );
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_status() {
    match parse_response(b"* STATUS blurdybloop (MESSAGES 231 UIDNEXT 44292)\r\n") {
        Ok((_, Response::MailboxData(MailboxDatum::Status { mailbox, status }))) => {
            assert_eq!(mailbox, "blurdybloop");
            assert_eq!(
                status,
                [
                    StatusAttribute::Messages(231),
                    StatusAttribute::UidNext(44292),
                ]
            );
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // Outlook server sends a STATUS response with a space in the end.
    match parse_response(b"* STATUS Sent (UIDNEXT 107) \r\n") {
        Ok((_, Response::MailboxData(MailboxDatum::Status { mailbox, status }))) => {
            assert_eq!(mailbox, "Sent");
            assert_eq!(status, [StatusAttribute::UidNext(107),]);
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // mail.163.com sends a STATUS response with an empty list when asked for (UIDNEXT)
    match parse_response(b"* STATUS \"INBOX\" ()\r\n") {
        Ok((_, Response::MailboxData(MailboxDatum::Status { mailbox, status }))) => {
            assert_eq!(mailbox, "INBOX");
            assert_eq!(status, []);
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_notify() {
    match parse_response(b"* 3501 EXPUNGE\r\n") {
        Ok((_, Response::Expunge(3501))) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
    match parse_response(b"* 3501 EXISTS\r\n") {
        Ok((_, Response::MailboxData(MailboxDatum::Exists(3501)))) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
    match parse_response(b"+ idling\r\n") {
        Ok((
            _,
            Response::Continue {
                code: None,
                information: Some(Cow::Borrowed("idling")),
            },
        )) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_search() {
    // also allow trailing whitespace in SEARCH responses
    for empty_response in &["* SEARCH\r\n", "* SEARCH \r\n"] {
        match parse_response(empty_response.as_bytes()) {
            Ok((_, Response::MailboxData(MailboxDatum::Search(ids)))) => {
                assert!(ids.is_empty());
            }
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }
    for response in &["* SEARCH 12345 67890\r\n", "* SEARCH 12345 67890 \r\n"] {
        match parse_response(response.as_bytes()) {
            Ok((_, Response::MailboxData(MailboxDatum::Search(ids)))) => {
                assert_eq!(ids[0], 12345);
                assert_eq!(ids[1], 67890);
            }
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }
}

#[test]
fn test_sort() {
    // also allow trailing whitespace in SEARCH responses
    for empty_response in &["* SORT\r\n", "* SORT \r\n"] {
        match parse_response(empty_response.as_bytes()) {
            Ok((_, Response::MailboxData(MailboxDatum::Sort(ids)))) => {
                assert!(ids.is_empty());
            }
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }
    for response in &["* SORT 12345 67890\r\n", "* SORT 12345 67890 \r\n"] {
        match parse_response(response.as_bytes()) {
            Ok((_, Response::MailboxData(MailboxDatum::Sort(ids)))) => {
                assert_eq!(ids[0], 12345);
                assert_eq!(ids[1], 67890);
            }
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }
}

#[test]
fn test_uid_fetch() {
    match parse_response(b"* 4 FETCH (UID 71372 RFC822.HEADER {10275}\r\n") {
        Err(nom::Err::Incomplete(nom::Needed::Size(size))) => {
            assert_eq!(size, NonZeroUsize::new(10275).unwrap());
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_uid_fetch_extra_space() {
    // DavMail inserts an extra space after RFC822.HEADER
    match parse_response(b"* 4 FETCH (UID 71372 RFC822.HEADER  {10275}\r\n") {
        Err(nom::Err::Incomplete(nom::Needed::Size(size))) => {
            assert_eq!(size, NonZeroUsize::new(10275).unwrap());
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_header_fields() {
    const RESPONSE: &[u8] = b"* 1 FETCH (UID 1 BODY[HEADER.FIELDS (CHAT-VERSION)] {21}\r\nChat-Version: 1.0\r\n\r\n)\r\n";

    match parse_response(RESPONSE) {
        Ok((_, Response::Fetch(_, _))) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_response_codes() {
    match parse_response(b"* OK [ALERT] Alert!\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::Ok,
                code: Some(ResponseCode::Alert),
                information: Some(Cow::Borrowed("Alert!")),
            },
        )) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }

    match parse_response(b"* NO [PARSE] Something\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::No,
                code: Some(ResponseCode::Parse),
                information: Some(Cow::Borrowed("Something")),
            },
        )) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }

    match parse_response(b"* OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::Ok,
                code: Some(ResponseCode::Capabilities(c)),
                information: Some(Cow::Borrowed("Logged in")),
            },
        )) => {
            assert_eq!(c.len(), 2);
            assert_eq!(c[0], Capability::Imap4rev1);
            assert_eq!(c[1], Capability::Atom(Cow::Borrowed("IDLE")));
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    match parse_response(b"* OK [CAPABILITY UIDPLUS IMAP4rev1 IDLE] Logged in\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::Ok,
                code: Some(ResponseCode::Capabilities(c)),
                information: Some(Cow::Borrowed("Logged in")),
            },
        )) => {
            assert_eq!(c.len(), 3);
            assert_eq!(c[0], Capability::Atom(Cow::Borrowed("UIDPLUS")));
            assert_eq!(c[1], Capability::Imap4rev1);
            assert_eq!(c[2], Capability::Atom(Cow::Borrowed("IDLE")));
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // Missing IMAP4rev1
    match parse_response(b"* OK [CAPABILITY UIDPLUS IDLE] Logged in\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::Ok,
                code: None,
                information: Some(Cow::Borrowed("[CAPABILITY UIDPLUS IDLE] Logged in")),
            },
        )) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }

    match parse_response(b"* NO [BADCHARSET] error\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::No,
                code: Some(ResponseCode::BadCharset(None)),
                information: Some(Cow::Borrowed("error")),
            },
        )) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }

    match parse_response(b"* NO [BADCHARSET (utf-8 latin1)] error\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::No,
                code: Some(ResponseCode::BadCharset(Some(v))),
                information: Some(Cow::Borrowed("error")),
            },
        )) => {
            assert_eq!(v.len(), 2);
            assert_eq!(v[0], "utf-8");
            assert_eq!(v[1], "latin1");
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }

    match parse_response(b"* NO [BADCHARSET ()] error\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::No,
                code: None,
                information: Some(Cow::Borrowed("[BADCHARSET ()] error")),
            },
        )) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_incomplete_fetch() {
    match parse_response(b"* 4644 FETCH (UID ") {
        Err(nom::Err::Incomplete(_)) => {}
        rsp => panic!("should be incomplete: {rsp:?}"),
    }
}

#[test]
fn test_fetch_response_whitespace_tolerance() {
    // Allow extra whitespace before the closing parenthesis.
    let input = b"* 11784 FETCH (UID 87567 INTERNALDATE \"06-May-2023 18:48:30 +0200\" RFC822.SIZE 5799845 )\r\n";
    assert!(parse_response(input).is_ok());
}

#[test]
fn test_continuation() {
    // regular RFC compliant
    match parse_response(b"+ \r\n") {
        Ok((
            _,
            Response::Continue {
                code: None,
                information: None,
            },
        )) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }

    // short version, sent by yandex
    match parse_response(b"+\r\n") {
        Ok((
            _,
            Response::Continue {
                code: None,
                information: None,
            },
        )) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_enabled() {
    match parse_response(b"* ENABLED QRESYNC X-GOOD-IDEA\r\n") {
        Ok((_, capabilities)) => assert_eq!(
            capabilities,
            Response::Capabilities(vec![
                Capability::Atom(Cow::Borrowed("QRESYNC")),
                Capability::Atom(Cow::Borrowed("X-GOOD-IDEA")),
            ])
        ),
        rsp => panic!("Unexpected response: {rsp:?}"),
    }
}

#[test]
fn test_flags() {
    // Invalid response (FLAGS can't include \*) from Zoho Mail server.
    //
    // As a workaround, such response is parsed without error.
    match parse_response(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)\r\n") {
        Ok((_, capabilities)) => assert_eq!(
            capabilities,
            Response::MailboxData(MailboxDatum::Flags(vec![
                Cow::Borrowed("\\Answered"),
                Cow::Borrowed("\\Flagged"),
                Cow::Borrowed("\\Deleted"),
                Cow::Borrowed("\\Seen"),
                Cow::Borrowed("\\Draft"),
                Cow::Borrowed("\\*")
            ]))
        ),
        rsp => panic!("Unexpected response: {rsp:?}"),
    }

    // Invalid response (FLAGS can't include ']') from some unknown providers.
    //
    // As a workaround, such response is parsed without error.
    match parse_response(b"* FLAGS (OIB-Seen-[Gmail]/All)\r\n") {
        Ok((_, capabilities)) => assert_eq!(
            capabilities,
            Response::MailboxData(MailboxDatum::Flags(vec![Cow::Borrowed(
                "OIB-Seen-[Gmail]/All"
            )]))
        ),
        rsp => panic!("Unexpected response: {rsp:?}"),
    }
}

#[test]
fn test_doubled_flag_prefixes() {
    let inputs: &[&[u8]] = &[
        b"* FLAGS (\\Answered \\Deleted \\Draft \\Flagged \\Seen \\\\Flagged \\\\Seen \\\\Answered)\r\n",
        b"* 1 FETCH (FLAGS (\\Answered \\Deleted \\Draft \\Flagged \\Seen \\\\Flagged \\\\Seen \\\\Answered))\r\n",
        b"* OK [PERMANENTFLAGS (\\Answered \\Deleted \\Draft \\Flagged \\Seen \\\\Flagged \\\\Seen \\\\Answered \\*)] Flags permitted.\r\n",
    ];
    for (index, input) in inputs.iter().enumerate() {
        let (remaining, response) = parse_response(input).unwrap();
        assert!(remaining.is_empty());
        let flags = match (index, response) {
            (0, Response::MailboxData(MailboxDatum::Flags(flags))) => flags,
            (1, Response::Fetch(1, mut attributes)) => {
                assert_eq!(attributes.len(), 1);
                match attributes.remove(0) {
                    AttributeValue::Flags(flags) => flags,
                    attribute => panic!("unexpected attribute {attribute:?}"),
                }
            }
            (
                2,
                Response::Data {
                    status: Status::Ok,
                    code: Some(ResponseCode::PermanentFlags(flags)),
                    information: Some(Cow::Borrowed("Flags permitted.")),
                },
            ) => flags,
            (_, response) => panic!("unexpected response {response:?}"),
        };
        let mut expected = vec![
            "\\Answered",
            "\\Deleted",
            "\\Draft",
            "\\Flagged",
            "\\Seen",
            "\\Flagged",
            "\\Seen",
            "\\Answered",
        ];
        if index == 2 {
            expected.push("\\*");
        }
        assert_eq!(flags, expected);
        assert!(flags.iter().all(|flag| matches!(flag, Cow::Borrowed(_))));
    }
}

#[test]
fn test_doubled_permanent_flag_wildcard() {
    match parse_response(b"* OK [PERMANENTFLAGS (\\Seen \\* \\\\*)] Flags permitted.\r\n") {
        Ok((
            [],
            Response::Data {
                status: Status::Ok,
                code: Some(ResponseCode::PermanentFlags(flags)),
                information: Some(Cow::Borrowed("Flags permitted.")),
            },
        )) => {
            assert_eq!(flags, vec!["\\Seen", "\\*", "\\*"]);
            assert!(flags.iter().all(|flag| matches!(flag, Cow::Borrowed(_))));
        }
        response => panic!("unexpected response {response:?}"),
    }
}

#[test]
fn test_tripled_flag_prefix_is_not_normalized_twice() {
    assert!(parse_response(b"* FLAGS (\\\\\\Seen)\r\n").is_err());
    assert!(parse_response(b"* 1 FETCH (FLAGS (\\\\\\Seen))\r\n").is_err());
    for input in [
        &b"* OK [PERMANENTFLAGS (\\\\\\Seen)] Flags permitted.\r\n"[..],
        &b"* OK [PERMANENTFLAGS (\\\\\\*)] Flags permitted.\r\n"[..],
    ] {
        match parse_response(input) {
            Ok((
                [],
                Response::Data {
                    status: Status::Ok,
                    code: None,
                    information: Some(Cow::Borrowed(_)),
                },
            )) => {}
            response => panic!("unexpected response {response:?}"),
        }
    }
}

#[test]
fn test_vanished() {
    match parse_response(b"* VANISHED (EARLIER) 1,2,3:8\r\n") {
        Ok((_, Response::Vanished { earlier, uids })) => {
            assert!(earlier);
            assert_eq!(uids.len(), 3);
            let v = &uids[0];
            assert_eq!(*v.start(), 1);
            assert_eq!(*v.end(), 1);
            let v = &uids[1];
            assert_eq!(*v.start(), 2);
            assert_eq!(*v.end(), 2);
            let v = &uids[2];
            assert_eq!(*v.start(), 3);
            assert_eq!(*v.end(), 8);
        }
        rsp => panic!("Unexpected response: {rsp:?}"),
    }

    match parse_response(b"* VANISHED 1,2,3:8,10\r\n") {
        Ok((_, Response::Vanished { earlier, uids })) => {
            assert!(!earlier);
            assert_eq!(uids.len(), 4);
        }
        rsp => panic!("Unexpected response: {rsp:?}"),
    }

    match parse_response(b"* VANISHED (EARLIER) 1\r\n") {
        Ok((_, Response::Vanished { earlier, uids })) => {
            assert!(earlier);
            assert_eq!(uids.len(), 1);
            assert_eq!(uids[0].clone().collect::<Vec<u32>>(), vec![1]);
        }
        rsp => panic!("Unexpected response: {rsp:?}"),
    }

    match parse_response(b"* VANISHED 1\r\n") {
        Ok((_, Response::Vanished { earlier, uids })) => {
            assert!(!earlier);
            assert_eq!(uids.len(), 1);
        }
        rsp => panic!("Unexpected response: {rsp:?}"),
    }

    assert!(parse_response(b"* VANISHED \r\n").is_err());
    assert!(parse_response(b"* VANISHED (EARLIER) \r\n").is_err());
}

#[test]
fn test_uidplus() {
    match dbg!(parse_response(
        b"* OK [APPENDUID 38505 3955] APPEND completed\r\n"
    )) {
        Ok((
            _,
            Response::Data {
                status: Status::Ok,
                code: Some(ResponseCode::AppendUid(38505, uid_set)),
                information: Some(Cow::Borrowed("APPEND completed")),
            },
        )) if uid_set == [3955.into()] => {}
        rsp => panic!("Unexpected response: {rsp:?}"),
    }
    match dbg!(parse_response(
        b"* OK [COPYUID 38505 304,319:320 3956:3958] Done\r\n"
    )) {
        Ok((
            _,
            Response::Data {
                status: Status::Ok,
                code: Some(ResponseCode::CopyUid(38505, uid_set_src, uid_set_dst)),
                information: Some(Cow::Borrowed("Done")),
            },
        )) if uid_set_src == [304.into(), (319..=320).into()]
            && uid_set_dst == [(3956..=3958).into()] => {}
        rsp => panic!("Unexpected response: {rsp:?}"),
    }
    match dbg!(parse_response(
        b"* NO [UIDNOTSTICKY] Non-persistent UIDs\r\n"
    )) {
        Ok((
            _,
            Response::Data {
                status: Status::No,
                code: Some(ResponseCode::UidNotSticky),
                information: Some(Cow::Borrowed("Non-persistent UIDs")),
            },
        )) => {}
        rsp => panic!("Unexpected response: {rsp:?}"),
    }
}

#[test]
fn test_imap_body_structure() {
    let test = b"\
    * 1569 FETCH (\
        BODYSTRUCTURE (\
            (\
                (\
                    (\
                        \"TEXT\" \"PLAIN\" \
                        (\"CHARSET\" \"ISO-8859-1\") NIL NIL \
                        \"QUOTED-PRINTABLE\" 833 30 NIL NIL NIL\
                    )\
                    (\
                        \"TEXT\" \"HTML\" \
                        (\"CHARSET\" \"ISO-8859-1\") NIL NIL \
                        \"QUOTED-PRINTABLE\" 3412 62 NIL \
                        (\"INLINE\" NIL) NIL\
                    ) \
                    \"ALTERNATIVE\" (\"BOUNDARY\" \"2__=fgrths\") NIL NIL\
                )\
                (\
                    \"IMAGE\" \"GIF\" \
                    (\"NAME\" \"485039.gif\") \"<2__=lgkfjr>\" NIL \
                    \"BASE64\" 64 NIL (\"INLINE\" (\"FILENAME\" \"485039.gif\")) \
                    NIL\
                ) \
                \"RELATED\" (\"BOUNDARY\" \"1__=fgrths\") NIL NIL\
            )\
            (\
                \"APPLICATION\" \"PDF\" \
                (\"NAME\" \"title.pdf\") \
                \"<1__=lgkfjr>\" NIL \"BASE64\" 333980 NIL \
                (\"ATTACHMENT\" (\"FILENAME\" \"title.pdf\")) NIL\
            ) \
            \"MIXED\" (\"BOUNDARY\" \"0__=fgrths\") NIL NIL\
        )\
    )\r\n";

    let (_, resp) = parse_response(test).unwrap();
    match resp {
        Response::Fetch(_, f) => {
            let bodystructure = f
                .iter()
                .flat_map(|f| match f {
                    AttributeValue::BodyStructure(e) => Some(e),
                    _ => None,
                })
                .next()
                .unwrap();

            let parser = BodyStructParser::new(bodystructure);

            let element = parser.search(|b: &BodyStructure| {
                matches!(b, BodyStructure::Basic { ref common, .. } if common.ty.ty == "APPLICATION")
            });

            assert_eq!(element, Some(vec![2]));
        }
        _ => panic!("invalid FETCH command test"),
    };
}

#[test]
fn test_parsing_of_quota_capability_in_login_response() {
    match parse_response(b"* OK [CAPABILITY IMAP4rev1 IDLE QUOTA] Logged in\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::Ok,
                code: Some(ResponseCode::Capabilities(c)),
                information: Some(Cow::Borrowed("Logged in")),
            },
        )) => {
            assert_eq!(c.len(), 3);
            assert_eq!(c[0], Capability::Imap4rev1);
            assert_eq!(c[1], Capability::Atom(Cow::Borrowed("IDLE")));
            assert_eq!(c[2], Capability::Atom(Cow::Borrowed("QUOTA")));
        }
        rsp => panic!("unexpected response {rsp:?}"),
    }
}

#[test]
fn test_parsing_of_bye_response() {
    match parse_response(b"* BYE\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::Bye,
                code: None,
                information: None,
            },
        )) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    };
    match parse_response(b"* BYE Autologout; idle for too long\r\n") {
        Ok((
            _,
            Response::Data {
                status: Status::Bye,
                code: None,
                information: Some(Cow::Borrowed("Autologout; idle for too long")),
            },
        )) => {}
        rsp => panic!("unexpected response {rsp:?}"),
    };
}
