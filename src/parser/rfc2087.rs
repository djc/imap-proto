//!
//! https://tools.ietf.org/html/rfc2087
//!
//! IMAP4 QUOTA extension
//!

use std::borrow::Cow;

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

use crate::parser::core::{astring_utf8, to_owned_cow};
use crate::parser::Response;

use super::core::number_64;

/// 5.1. QUOTA Response (https://tools.ietf.org/html/rfc2087#section-5.1)
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct Quota<'a> {
    /// quota root name
    pub root_name: Cow<'a, str>,
    pub resources: Vec<QuotaResource<'a>>,
}

impl<'a> Quota<'a> {
    pub fn into_owned(self) -> Quota<'static> {
        Quota {
            root_name: to_owned_cow(self.root_name),
            resources: self.resources.into_iter().map(|r| r.into_owned()).collect(),
        }
    }
}

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

/// 5.1. QUOTA Response (https://tools.ietf.org/html/rfc2087#section-5.1)
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct QuotaResource<'a> {
    pub name: QuotaResourceName<'a>,
    /// current usage of the resource
    pub usage: u64,
    /// resource limit
    pub limit: u64,
}

impl<'a> QuotaResource<'a> {
    pub fn into_owned(self) -> QuotaResource<'static> {
        QuotaResource {
            name: self.name.into_owned(),
            usage: self.usage,
            limit: self.limit,
        }
    }
}

/// ```ignore
/// quota_resource  ::= atom SP number SP number
/// ```
pub(crate) fn quota_resource(i: &[u8]) -> IResult<&[u8], QuotaResource<'_>> {
    let (rest, (name, _, usage, _, limit)) =
        (quota_resource_name, space1, number_64, space1, number_64).parse(i)?;

    Ok((rest, QuotaResource { name, usage, limit }))
}

/// https://tools.ietf.org/html/rfc2087#section-3
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum QuotaResourceName<'a> {
    /// Sum of messages' RFC822.SIZE, in units of 1024 octets
    Storage,
    /// Number of messages
    Message,
    Atom(Cow<'a, str>),
}

impl<'a> QuotaResourceName<'a> {
    pub fn into_owned(self) -> QuotaResourceName<'static> {
        match self {
            QuotaResourceName::Message => QuotaResourceName::Message,
            QuotaResourceName::Storage => QuotaResourceName::Storage,
            QuotaResourceName::Atom(v) => QuotaResourceName::Atom(to_owned_cow(v)),
        }
    }
}

pub(crate) fn quota_resource_name(i: &[u8]) -> IResult<&[u8], QuotaResourceName<'_>> {
    alt((
        map(tag_no_case("STORAGE"), |_| QuotaResourceName::Storage),
        map(tag_no_case("MESSAGE"), |_| QuotaResourceName::Message),
        map(astring_utf8, QuotaResourceName::Atom),
    ))
    .parse(i)
}

/// 5.2. QUOTAROOT Response (https://tools.ietf.org/html/rfc2087#section-5.2)
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct QuotaRoot<'a> {
    /// mailbox name
    pub mailbox_name: Cow<'a, str>,
    /// zero or more quota root names
    pub quota_root_names: Vec<Cow<'a, str>>,
}

impl<'a> QuotaRoot<'a> {
    pub fn into_owned(self) -> QuotaRoot<'static> {
        QuotaRoot {
            mailbox_name: to_owned_cow(self.mailbox_name),
            quota_root_names: self
                .quota_root_names
                .into_iter()
                .map(to_owned_cow)
                .collect(),
        }
    }
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
