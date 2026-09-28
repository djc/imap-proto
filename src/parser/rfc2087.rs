//!
//! https://tools.ietf.org/html/rfc2087
//!
//! IMAP4 QUOTA extension
//!

use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    character::streaming::space1,
    combinator::map,
    multi::many0,
    multi::separated_list0,
    sequence::{delimited, preceded},
    IResult, Parser,
};

use crate::parser::core::astring_utf8;
use crate::types::*;

use super::core::number_64;

/// 5.1. QUOTA Response
/// ```ignore
/// quota_response  ::= "QUOTA" SP astring SP quota_list
/// ```
pub(crate) fn quota(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    let (rest, (_, _, root_name, _, resources)) = (
        tag_no_case("QUOTA"),
        space1,
        astring_utf8,
        space1,
        quota_list,
    )
        .parse(i)?;

    Ok((
        rest,
        Response::Quota(Quota {
            root_name,
            resources,
        }),
    ))
}

/// ```ignore
/// quota_list  ::= "(" #quota_resource ")"
/// ```
pub(crate) fn quota_list(i: &[u8]) -> IResult<&[u8], Vec<QuotaResource<'_>>> {
    delimited(tag("("), separated_list0(space1, quota_resource), tag(")")).parse(i)
}

/// ```ignore
/// quota_resource  ::= atom SP number SP number
/// ```
pub(crate) fn quota_resource(i: &[u8]) -> IResult<&[u8], QuotaResource<'_>> {
    let (rest, (name, _, usage, _, limit)) =
        (quota_resource_name, space1, number_64, space1, number_64).parse(i)?;

    Ok((rest, QuotaResource { name, usage, limit }))
}

pub(crate) fn quota_resource_name(i: &[u8]) -> IResult<&[u8], QuotaResourceName<'_>> {
    alt((
        map(tag_no_case("STORAGE"), |_| QuotaResourceName::Storage),
        map(tag_no_case("MESSAGE"), |_| QuotaResourceName::Message),
        map(astring_utf8, QuotaResourceName::Atom),
    ))
    .parse(i)
}

/// 5.2. QUOTAROOT Response
/// ```ignore
/// quotaroot_response ::= "QUOTAROOT" SP astring *(SP astring)
/// ```
pub(crate) fn quota_root(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    let (rest, (_, _, mailbox_name, quota_root_names)) = (
        tag_no_case("QUOTAROOT"),
        space1,
        astring_utf8,
        many0(preceded(space1, astring_utf8)),
    )
        .parse(i)?;

    Ok((
        rest,
        Response::QuotaRoot(QuotaRoot {
            mailbox_name,
            quota_root_names,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use std::borrow::Cow;

    #[test]
    fn test_quota() {
        assert_matches!(
            quota(b"QUOTA \"\" (STORAGE 10 512)"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    Response::Quota(Quota {
                        root_name: Cow::Borrowed(""),
                        resources: vec![QuotaResource {
                            name: QuotaResourceName::Storage,
                            usage: 10,
                            limit: 512
                        }]
                    })
                );
            }
        );
    }

    #[test]
    fn test_quota_spaces() {
        // Archiveopteryx 3.2.0 generates QUOTA resources with double space.
        // This is a test of a workaround for such incorrect implementation of QUOTA.
        assert_matches!(
            quota(b"QUOTA \"\" (STORAGE 0 2147483647 MESSAGE 0  2147483647)"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    Response::Quota(Quota {
                        root_name: Cow::Borrowed(""),
                        resources: vec![QuotaResource {
                            name: QuotaResourceName::Storage,
                            usage: 0,
                            limit: 2147483647
                        }, QuotaResource {
                            name: QuotaResourceName::Message,
                            usage: 0,
                            limit: 2147483647
                        }]
                    })
                );
            }
        );
    }

    #[test]
    fn test_quota_response_data() {
        assert_matches!(
            crate::parser::rfc3501::response_data(b"* QUOTA \"\" (STORAGE 10 512)\r\n"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    Response::Quota(Quota {
                        root_name: Cow::Borrowed(""),
                        resources: vec![QuotaResource {
                            name: QuotaResourceName::Storage,
                            usage: 10,
                            limit: 512
                        }]
                    })
                );
            }
        );
    }

    #[test]
    fn test_quota_list() {
        assert_matches!(
            quota_list(b"(STORAGE 10 512)"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    vec![QuotaResource {
                        name: QuotaResourceName::Storage,
                        usage: 10,
                        limit: 512
                    }]
                );
            }
        );

        assert_matches!(
            quota_list(b"(MESSAGE 100 512)"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    vec![QuotaResource {
                        name: QuotaResourceName::Message,
                        usage: 100,
                        limit: 512
                    }]
                );
            }
        );

        assert_matches!(
            quota_list(b"(DAILY 55 200)"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    vec![QuotaResource {
                        name: QuotaResourceName::Atom(Cow::Borrowed("DAILY")),
                        usage: 55,
                        limit: 200
                    }]
                );
            }
        );
    }

    #[test]
    fn test_quota_root_response_data() {
        assert_matches!(
            crate::parser::rfc3501::response_data("* QUOTAROOT INBOX \"\"\r\n".as_bytes()),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    Response::QuotaRoot(QuotaRoot{
                        mailbox_name: Cow::Borrowed("INBOX"),
                        quota_root_names: vec![Cow::Borrowed("")]
                    })
                );
            }
        );
    }

    fn terminated_quota_root(i: &[u8]) -> IResult<&[u8], Response<'_>> {
        nom::sequence::terminated(quota_root, nom::bytes::streaming::tag("\r\n")).parse(i)
    }

    #[test]
    fn test_quota_root_without_root_names() {
        assert_matches!(
            terminated_quota_root(b"QUOTAROOT comp.mail.mime\r\n"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    Response::QuotaRoot(QuotaRoot{
                        mailbox_name: Cow::Borrowed("comp.mail.mime"),
                        quota_root_names: vec![]
                    })
                );
            }
        );
    }

    #[test]
    fn test_quota_root2() {
        assert_matches!(
            terminated_quota_root(b"QUOTAROOT INBOX HU\r\n"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    Response::QuotaRoot(QuotaRoot{
                        mailbox_name: Cow::Borrowed("INBOX"),
                        quota_root_names: vec![Cow::Borrowed("HU")]
                    })
                );
            }
        );

        assert_matches!(
            terminated_quota_root(b"QUOTAROOT INBOX \"\"\r\n"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    Response::QuotaRoot(QuotaRoot{
                        mailbox_name: Cow::Borrowed("INBOX"),
                        quota_root_names: vec![Cow::Borrowed("")]
                    })
                );
            }
        );

        assert_matches!(
            terminated_quota_root(b"QUOTAROOT \"Inbox\" \"#Account\"\r\n"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    Response::QuotaRoot(QuotaRoot{
                        mailbox_name: Cow::Borrowed("Inbox"),
                        quota_root_names: vec![Cow::Borrowed("#Account")]
                    })
                );
            }
        );

        assert_matches!(
            terminated_quota_root(b"QUOTAROOT \"Inbox\" \"#Account\" \"#Mailbox\"\r\n"),
            Ok((_, r)) => {
                assert_eq!(
                    r,
                    Response::QuotaRoot(QuotaRoot{
                        mailbox_name: Cow::Borrowed("Inbox"),
                        quota_root_names: vec![Cow::Borrowed("#Account"), Cow::Borrowed("#Mailbox")]
                    })
                );
            }
        );
    }
}
