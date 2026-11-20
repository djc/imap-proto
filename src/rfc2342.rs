//! The IMAP NAMESPACE Extension
//!
//! <https://tools.ietf.org/html/rfc2342>
//!
//! Namespace response extensions are defined in
//! <https://tools.ietf.org/html/rfc4466#section-2.1>

use std::borrow::Cow;

use nom::{
    branch::alt,
    bytes::complete::tag_no_case,
    character::complete::{char, space0, space1},
    combinator::{map, map_opt},
    multi::{many0, many1, separated_list1},
    sequence::{delimited, preceded},
    IResult, Parser,
};

use crate::core::{nil, string_utf8, to_owned_cow};
use crate::Response;

/// A namespace description: a mailbox name prefix, its hierarchy delimiter
/// and any response extensions.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Namespace<'a> {
    /// The mailbox name prefix, as sent by the server (it may be in
    /// modified UTF-7 and is not decoded).
    pub prefix: Cow<'a, str>,
    /// The hierarchy delimiter, or `None` if the namespace is flat (`NIL`).
    pub delimiter: Option<char>,
    /// RFC 4466 namespace response extensions.
    pub extensions: Vec<NamespaceExtension<'a>>,
}

impl Namespace<'_> {
    pub fn into_owned(self) -> Namespace<'static> {
        Namespace {
            prefix: to_owned_cow(self.prefix),
            delimiter: self.delimiter,
            extensions: self
                .extensions
                .into_iter()
                .map(NamespaceExtension::into_owned)
                .collect(),
        }
    }
}

/// An RFC 4466 namespace response extension: a name and its values.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct NamespaceExtension<'a> {
    pub name: Cow<'a, str>,
    pub values: Vec<Cow<'a, str>>,
}

impl NamespaceExtension<'_> {
    pub fn into_owned(self) -> NamespaceExtension<'static> {
        NamespaceExtension {
            name: to_owned_cow(self.name),
            values: self.values.into_iter().map(to_owned_cow).collect(),
        }
    }
}

// Namespace-Response-Extension = SP string SP "(" string *(SP string) ")"
// [RFC4466 - Formal Syntax](https://tools.ietf.org/html/rfc4466#section-4)
fn namespace_extension(i: &[u8]) -> IResult<&[u8], NamespaceExtension<'_>> {
    map(
        preceded(
            space1,
            (
                string_utf8,
                space1,
                delimited(char('('), separated_list1(space1, string_utf8), char(')')),
            ),
        ),
        |(name, _, values)| NamespaceExtension { name, values },
    )
    .parse(i)
}

// Delimiter = DQUOTE QUOTED-CHAR DQUOTE / nil
fn delimiter(i: &[u8]) -> IResult<&[u8], Option<char>> {
    alt((
        map(nil, |_| None),
        map_opt(string_utf8, |s| {
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => Some(Some(c)),
                _ => None,
            }
        }),
    ))
    .parse(i)
}

// Namespace = "(" string SP (DQUOTE QUOTED-CHAR DQUOTE / nil)
//             [Namespace-Response-Extensions] ")"
// [RFC2342 - Formal Syntax](https://tools.ietf.org/html/rfc2342#section-7)
fn namespace(i: &[u8]) -> IResult<&[u8], Namespace<'_>> {
    map(
        delimited(
            char('('),
            (string_utf8, space1, delimiter, many0(namespace_extension)),
            char(')'),
        ),
        |(prefix, _, delimiter, extensions)| Namespace {
            prefix,
            delimiter,
            extensions,
        },
    )
    .parse(i)
}

// Namespace = nil / "(" 1*Namespace_Descr ")"
fn namespace_group(i: &[u8]) -> IResult<&[u8], Option<Vec<Namespace<'_>>>> {
    alt((
        map(nil, |_| None),
        map(
            delimited(
                char('('),
                // The descriptors are adjacent; tolerate stray spaces.
                many1(delimited(space0, namespace, space0)),
                char(')'),
            ),
            Some,
        ),
    ))
    .parse(i)
}

// Namespace_Response = "*" SP "NAMESPACE" SP Namespace SP Namespace SP Namespace
// [RFC2342 - Formal Syntax](https://tools.ietf.org/html/rfc2342#section-7)
pub(crate) fn namespace_response(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    map(
        (
            tag_no_case("NAMESPACE"),
            space1,
            namespace_group,
            space1,
            namespace_group,
            space1,
            namespace_group,
        ),
        |(_, _, personal, _, other_users, _, shared)| Response::Namespace {
            personal,
            other_users,
            shared,
        },
    )
    .parse(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(prefix: &'static str, delimiter: Option<char>) -> Namespace<'static> {
        Namespace {
            prefix: Cow::Borrowed(prefix),
            delimiter,
            extensions: Vec::new(),
        }
    }

    fn parse(i: &[u8]) -> Response<'_> {
        match Response::parse(i) {
            Ok((b"", r)) => r,
            other => panic!("unexpected result {other:?}"),
        }
    }

    #[test]
    fn test_dovecot() {
        assert_eq!(
            parse(b"* NAMESPACE ((\"\" \"/\")) ((\"shared/\" \"/\")) NIL\r\n"),
            Response::Namespace {
                personal: Some(vec![ns("", Some('/'))]),
                other_users: Some(vec![ns("shared/", Some('/'))]),
                shared: None,
            }
        );
    }

    #[test]
    fn test_cyrus() {
        assert_eq!(
            parse(b"* NAMESPACE ((\"INBOX.\" \".\")) ((\"user.\" \".\")) ((\"\" \".\"))\r\n"),
            Response::Namespace {
                personal: Some(vec![ns("INBOX.", Some('.'))]),
                other_users: Some(vec![ns("user.", Some('.'))]),
                shared: Some(vec![ns("", Some('.'))]),
            }
        );
    }

    #[test]
    fn test_gmail() {
        assert_eq!(
            parse(b"* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n"),
            Response::Namespace {
                personal: Some(vec![ns("", Some('/'))]),
                other_users: None,
                shared: None,
            }
        );
    }

    #[test]
    fn test_multiple_descriptors_and_nil_delimiter() {
        // RFC 2342 section 5, example 5.3
        assert_eq!(
            parse(
                b"* NAMESPACE ((\"\" \"/\")(\"#mbox/\" \"/\")) \
                  ((\"~\" \"/\")) ((\"#shared/\" \"/\")(\"#public/\" NIL))\r\n"
            ),
            Response::Namespace {
                personal: Some(vec![ns("", Some('/')), ns("#mbox/", Some('/'))]),
                other_users: Some(vec![ns("~", Some('/'))]),
                shared: Some(vec![ns("#shared/", Some('/')), ns("#public/", None)]),
            }
        );
    }

    #[test]
    fn test_case_insensitive_and_trailing_space() {
        assert_eq!(
            parse(b"* namespace ((\"\" \"/\")) NIL NIL \r\n"),
            Response::Namespace {
                personal: Some(vec![ns("", Some('/'))]),
                other_users: None,
                shared: None,
            }
        );
    }

    #[test]
    fn test_quoted_escapes() {
        assert_eq!(
            parse(b"* NAMESPACE ((\"a\\\"b\\\\c/\" \"\\\\\")) NIL NIL\r\n"),
            Response::Namespace {
                personal: Some(vec![ns("a\"b\\c/", Some('\\'))]),
                other_users: None,
                shared: None,
            }
        );
    }

    #[test]
    fn test_non_ascii_prefixes() {
        // Modified UTF-7 is passed through undecoded.
        assert_eq!(
            parse(b"* NAMESPACE ((\"&AOQ-/\" \"/\")) ((\"Gl\xc3\xa4ser.\" \".\")) NIL\r\n"),
            Response::Namespace {
                personal: Some(vec![ns("&AOQ-/", Some('/'))]),
                other_users: Some(vec![ns("Gl\u{e4}ser.", Some('.'))]),
                shared: None,
            }
        );
    }

    #[test]
    fn test_extensions() {
        assert_eq!(
            parse(
                b"* NAMESPACE ((\"\" \"/\" \"TRANSLATION\" (\"Pers\xc3\xb6nlich\" \"x\") \"FLAG\" (\"a\"))) NIL NIL\r\n"
            ),
            Response::Namespace {
                personal: Some(vec![Namespace {
                    prefix: Cow::Borrowed(""),
                    delimiter: Some('/'),
                    extensions: vec![
                        NamespaceExtension {
                            name: Cow::Borrowed("TRANSLATION"),
                            values: vec![Cow::Borrowed("Pers\u{f6}nlich"), Cow::Borrowed("x")],
                        },
                        NamespaceExtension {
                            name: Cow::Borrowed("FLAG"),
                            values: vec![Cow::Borrowed("a")],
                        },
                    ],
                }]),
                other_users: None,
                shared: None,
            }
        );
    }

    #[test]
    fn test_into_owned() {
        let owned = {
            let line = b"* NAMESPACE ((\"INBOX.\" \".\" \"X\" (\"y\"))) NIL NIL\r\n".to_vec();
            Response::parse(&line).unwrap().1.into_owned()
        };
        assert_matches::assert_matches!(
            owned,
            Response::Namespace { personal: Some(p), .. } => {
                assert_eq!(p[0].prefix, "INBOX.");
                assert_eq!(p[0].extensions[0].values, vec!["y"]);
            }
        );
    }

    #[test]
    fn test_invalid() {
        for bad in [
            // an empty group is invalid
            &b"* NAMESPACE () NIL NIL\r\n"[..],
            // delimiter must be a single character
            b"* NAMESPACE ((\"\" \"//\")) NIL NIL\r\n",
            b"* NAMESPACE ((\"\" \"\")) NIL NIL\r\n",
            // all three groups are required
            b"* NAMESPACE ((\"\" \"/\")) NIL\r\n",
            // an extension needs a non-empty value list
            b"* NAMESPACE ((\"\" \"/\" \"X\" ())) NIL NIL\r\n",
        ] {
            assert!(
                Response::parse(bad).map_or(true, |(rest, _)| !rest.is_empty()),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
