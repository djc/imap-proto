//!
//! <https://tools.ietf.org/html/rfc5464>
//!
//! IMAP METADATA extension
//!

use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    combinator::map,
    multi::separated_list0,
    IResult, Parser,
};
use std::borrow::Cow;

use crate::{
    core::*,
    rfc3501::{MailboxDatum, ResponseCode},
    Response,
};

fn is_entry_component_char(c: u8) -> bool {
    c < 0x80 && c > 0x19 && c != b'*' && c != b'%' && c != b'/'
}

enum EntryParseStage<'a> {
    PrivateShared,
    Admin(usize),
    VendorComment(usize),
    Path(usize),
    Done(usize),
    Fail(nom::Err<&'a [u8]>),
}

fn check_private_shared(i: &[u8]) -> EntryParseStage<'_> {
    if i.starts_with(b"/private") {
        EntryParseStage::VendorComment(8)
    } else if i.starts_with(b"/shared") {
        EntryParseStage::Admin(7)
    } else {
        EntryParseStage::Fail(nom::Err::Error(
            b"Entry Name doesn't start with /private or /shared",
        ))
    }
}

fn check_admin(i: &[u8], l: usize) -> EntryParseStage<'_> {
    if i[l..].starts_with(b"/admin") {
        EntryParseStage::Path(l + 6)
    } else {
        EntryParseStage::VendorComment(l)
    }
}

fn check_vendor_comment(i: &[u8], l: usize) -> EntryParseStage<'_> {
    if i[l..].starts_with(b"/comment") {
        EntryParseStage::Path(l + 8)
    } else if i[l..].starts_with(b"/vendor") {
        //make sure vendor name is present
        if i.len() < l + 9 || i[l + 7] != b'/' || !is_entry_component_char(i[l + 8]) {
            EntryParseStage::Fail(nom::Err::Incomplete(nom::Needed::Unknown))
        } else {
            EntryParseStage::Path(l + 7)
        }
    } else {
        EntryParseStage::Fail(nom::Err::Error(
            b"Entry name is not continued with /admin, /vendor or /comment",
        ))
    }
}

fn check_path(i: &[u8], l: usize) -> EntryParseStage<'_> {
    if i.len() == l || i[l] == b' ' || i[l] == b'\r' {
        return EntryParseStage::Done(l);
    } else if i[l] != b'/' {
        return EntryParseStage::Fail(nom::Err::Error(b"Entry name path is corrupted"));
    }
    for j in 1..(i.len() - l) {
        if !is_entry_component_char(i[l + j]) {
            return EntryParseStage::Path(l + j);
        }
    }
    EntryParseStage::Done(i.len())
}

fn check_entry_name(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let mut stage = EntryParseStage::PrivateShared;
    loop {
        match stage {
            EntryParseStage::PrivateShared => {
                stage = check_private_shared(i);
            }
            EntryParseStage::Admin(l) => {
                stage = check_admin(i, l);
            }
            EntryParseStage::VendorComment(l) => {
                stage = check_vendor_comment(i, l);
            }
            EntryParseStage::Path(l) => {
                stage = check_path(i, l);
            }
            EntryParseStage::Done(l) => {
                return Ok((&i[l..], &i[..l]));
            }
            EntryParseStage::Fail(nom::Err::Error(err_msg)) => {
                return std::result::Result::Err(nom::Err::Error(nom::error::Error::new(
                    err_msg,
                    nom::error::ErrorKind::Verify,
                )));
            }
            EntryParseStage::Fail(nom::Err::Incomplete(reason)) => {
                return std::result::Result::Err(nom::Err::Incomplete(reason));
            }
            _ => panic!("Entry name verification failure"),
        }
    }
}

fn entry_name(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let astring_res = astring(i)?;
    check_entry_name(astring_res.1)?;
    Ok(astring_res)
}

fn slice_to_str(i: &[u8]) -> &str {
    std::str::from_utf8(i).unwrap()
}

fn nil_value(i: &[u8]) -> IResult<&[u8], Option<String>> {
    map(tag_no_case("NIL"), |_| None).parse(i)
}

fn string_value(i: &[u8]) -> IResult<&[u8], Option<String>> {
    map(alt((quoted, literal)), |s| {
        Some(slice_to_str(s).to_string())
    })
    .parse(i)
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Metadata {
    pub entry: String,
    pub value: Option<String>,
}

fn keyval_list(i: &[u8]) -> IResult<&[u8], Vec<Metadata>> {
    parenthesized_nonempty_list(map(
        (
            map(entry_name, slice_to_str),
            tag(" "),
            alt((nil_value, string_value)),
        ),
        |(key, _, value)| Metadata {
            entry: key.to_string(),
            value,
        },
    ))
    .parse(i)
}

fn entry_list(i: &[u8]) -> IResult<&[u8], Vec<Cow<'_, str>>> {
    separated_list0(tag(" "), map(map(entry_name, slice_to_str), Cow::Borrowed)).parse(i)
}

fn metadata_common(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, (_, mbox, _)) = (tag_no_case("METADATA "), quoted, tag(" ")).parse(i)?;
    Ok((i, mbox))
}

// [RFC5464 - 4.4.1 METADATA Response with values]
pub(crate) fn metadata_solicited(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    let (i, (mailbox, values)) = (metadata_common, keyval_list).parse(i)?;
    Ok((
        i,
        Response::MailboxData(MailboxDatum::MetadataSolicited {
            mailbox: Cow::Borrowed(slice_to_str(mailbox)),
            values,
        }),
    ))
}

// [RFC5464 - 4.4.2 Unsolicited METADATA Response without values]
pub(crate) fn metadata_unsolicited(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    let (i, (mailbox, values)) = (metadata_common, entry_list).parse(i)?;
    Ok((
        i,
        Response::MailboxData(MailboxDatum::MetadataUnsolicited {
            mailbox: Cow::Borrowed(slice_to_str(mailbox)),
            values,
        }),
    ))
}

// There are any entries with values larger than the MAXSIZE limit given to GETMETADATA.
// Extends resp-test-code defined in rfc3501.
// [RFC5464 - 4.2.1 MAXSIZE GETMETADATA Command Option](https://tools.ietf.org/html/rfc5464#section-4.2.1)
// [RFC5464 - 5. Formal Syntax - resp-text-code](https://tools.ietf.org/html/rfc5464#section-5)
pub(crate) fn resp_text_code_metadata_long_entries(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    let (i, (_, num)) = (tag_no_case("METADATA LONGENTRIES "), number_64).parse(i)?;
    Ok((i, ResponseCode::MetadataLongEntries(num)))
}

// Server is unable to set an annotation because the size of its value is too large.
// Extends resp-test-code defined in rfc3501.
// [RFC5464 - 4.3 SETMETADATA Command](https://tools.ietf.org/html/rfc5464#section-4.3)
// [RFC5464 - 5. Formal Syntax - resp-text-code](https://tools.ietf.org/html/rfc5464#section-5)
pub(crate) fn resp_text_code_metadata_max_size(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    let (i, (_, num)) = (tag_no_case("METADATA MAXSIZE "), number_64).parse(i)?;
    Ok((i, ResponseCode::MetadataMaxSize(num)))
}

// Server is unable to set a new annotation because the maximum number of allowed annotations has already been reached.
// Extends resp-test-code defined in rfc3501.
// [RFC5464 - 4.3 SETMETADATA Command](https://tools.ietf.org/html/rfc5464#section-4.3)
// [RFC5464 - 5. Formal Syntax - resp-text-code](https://tools.ietf.org/html/rfc5464#section-5)
pub(crate) fn resp_text_code_metadata_too_many(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    let (i, _) = tag_no_case("METADATA TOOMANY")(i)?;
    Ok((i, ResponseCode::MetadataTooMany))
}

// Server is unable to set a new annotation because it does not support private annotations on one of the specified mailboxes.
// Extends resp-test-code defined in rfc3501.
// [RFC5464 - 4.3 SETMETADATA Command](https://tools.ietf.org/html/rfc5464#section-4.3)
// [RFC5464 - 5. Formal Syntax - resp-text-code](https://tools.ietf.org/html/rfc5464#section-5)
pub(crate) fn resp_text_code_metadata_no_private(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    let (i, _) = tag_no_case("METADATA NOPRIVATE")(i)?;
    Ok((i, ResponseCode::MetadataNoPrivate))
}

#[cfg(test)]
mod tests {
    use super::{metadata_solicited, metadata_unsolicited, MailboxDatum, Response, ResponseCode};
    use crate::rfc3501::{Outcome, Status};
    use std::borrow::Cow;

    #[test]
    fn test_solicited_fail_1() {
        match metadata_solicited(b"METADATA \"\" (/asdfg \"asdf\")\r\n") {
            Err(_) => {}
            _ => panic!("Error required when entry name is not starting with /private or /shared"),
        }
    }

    #[test]
    fn test_solicited_fail_2() {
        match metadata_solicited(b"METADATA \"\" (/shared/asdfg \"asdf\")\r\n") {
            Err(_) => {}
            _ => panic!(
                "Error required when in entry name /shared \
                 is not continued with /admin, /comment or /vendor"
            ),
        }
    }

    #[test]
    fn test_solicited_fail_3() {
        match metadata_solicited(b"METADATA \"\" (/private/admin \"asdf\")\r\n") {
            Err(_) => {}
            _ => panic!(
                "Error required when in entry name /private \
                 is not continued with /comment or /vendor"
            ),
        }
    }

    #[test]
    fn test_solicited_fail_4() {
        match metadata_solicited(b"METADATA \"\" (/shared/vendor \"asdf\")\r\n") {
            Err(_) => {}
            _ => panic!("Error required when vendor name is not provided."),
        }
    }

    #[test]
    fn test_solicited_success() {
        match metadata_solicited(
            b"METADATA \"mbox\" (/shared/vendor/vendorname \"asdf\" \
              /private/comment/a \"bbb\")\r\n",
        ) {
            Ok((i, Response::MailboxData(MailboxDatum::MetadataSolicited { mailbox, values }))) => {
                assert_eq!(mailbox, "mbox");
                assert_eq!(i, b"\r\n");
                assert_eq!(values.len(), 2);
                assert_eq!(values[0].entry, "/shared/vendor/vendorname");
                assert_eq!(
                    values[0]
                        .value
                        .as_ref()
                        .expect("None value is not expected"),
                    "asdf"
                );
                assert_eq!(values[1].entry, "/private/comment/a");
                assert_eq!(
                    values[1]
                        .value
                        .as_ref()
                        .expect("None value is not expected"),
                    "bbb"
                );
            }
            _ => panic!("Correct METADATA response is not parsed properly."),
        }
    }

    #[test]
    fn test_literal_success() {
        // match metadata_solicited(b"METADATA \"\" (/shared/vendor/vendor.coi/a \"AAA\")\r\n")
        match metadata_solicited(b"METADATA \"\" (/shared/vendor/vendor.coi/a {3}\r\nAAA)\r\n") {
            Ok((i, Response::MailboxData(MailboxDatum::MetadataSolicited { mailbox, values }))) => {
                assert_eq!(mailbox, "");
                assert_eq!(i, b"\r\n");
                assert_eq!(values.len(), 1);
                assert_eq!(values[0].entry, "/shared/vendor/vendor.coi/a");
                assert_eq!(
                    values[0]
                        .value
                        .as_ref()
                        .expect("None value is not expected"),
                    "AAA"
                );
            }
            Err(e) => panic!("ERR: {e:?}"),
            _ => panic!("Strange failure"),
        }
    }

    #[test]
    fn test_nil_success() {
        match metadata_solicited(b"METADATA \"\" (/shared/comment NIL /shared/admin NIL)\r\n") {
            Ok((i, Response::MailboxData(MailboxDatum::MetadataSolicited { mailbox, values }))) => {
                assert_eq!(mailbox, "");
                assert_eq!(i, b"\r\n");
                assert_eq!(values.len(), 2);
                assert_eq!(values[0].entry, "/shared/comment");
                assert_eq!(values[0].value, None);
                assert_eq!(values[1].entry, "/shared/admin");
                assert_eq!(values[1].value, None);
            }
            Err(e) => panic!("ERR: {e:?}"),
            _ => panic!("Strange failure"),
        }
    }

    #[test]
    fn test_unsolicited_success() {
        match metadata_unsolicited(b"METADATA \"theBox\" /shared/admin/qwe /private/comment/a\r\n")
        {
            Ok((
                i,
                Response::MailboxData(MailboxDatum::MetadataUnsolicited { mailbox, values }),
            )) => {
                assert_eq!(i, b"\r\n");
                assert_eq!(mailbox, "theBox");
                assert_eq!(values.len(), 2);
                assert_eq!(values[0], "/shared/admin/qwe");
                assert_eq!(values[1], "/private/comment/a");
            }
            _ => panic!("Correct METADATA response is not parsed properly."),
        }
    }

    #[test]
    fn test_response_codes() {
        match Response::parse(b"* OK [METADATA LONGENTRIES 123] Some entries omitted.\r\n") {
            Ok((
                _,
                Response::Data {
                    status: Status::Ok,
                    outcome:
                        Outcome {
                            code: Some(ResponseCode::MetadataLongEntries(123)),
                            information: Some(Cow::Borrowed("Some entries omitted.")),
                        },
                },
            )) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }

        match Response::parse(b"* NO [METADATA MAXSIZE 123] Annotation too large.\r\n") {
            Ok((
                _,
                Response::Data {
                    status: Status::No,
                    outcome:
                        Outcome {
                            code: Some(ResponseCode::MetadataMaxSize(123)),
                            information: Some(Cow::Borrowed("Annotation too large.")),
                        },
                },
            )) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }

        match Response::parse(b"* NO [METADATA TOOMANY] Too many annotations.\r\n") {
            Ok((
                _,
                Response::Data {
                    status: Status::No,
                    outcome:
                        Outcome {
                            code: Some(ResponseCode::MetadataTooMany),
                            information: Some(Cow::Borrowed("Too many annotations.")),
                        },
                },
            )) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }

        match Response::parse(b"* NO [METADATA NOPRIVATE] Private annotations not supported.\r\n") {
            Ok((
                _,
                Response::Data {
                    status: Status::No,
                    outcome:
                        Outcome {
                            code: Some(ResponseCode::MetadataNoPrivate),
                            information: Some(Cow::Borrowed("Private annotations not supported.")),
                        },
                },
            )) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }
}
