//!
//!
//! https://tools.ietf.org/html/rfc2971
//!
//! The IMAP4 ID extension
//!

use std::{borrow::Cow, collections::HashMap};

use nom::{
    branch::alt,
    bytes::complete::tag_no_case,
    character::complete::{char, space0, space1},
    combinator::map,
    multi::many0,
    sequence::{preceded, separated_pair},
    IResult, Parser,
};

use crate::{
    core::{nil, nstring_utf8, string_utf8},
    Response,
};

// A single id parameter (field and value).
// Format: string SPACE nstring
// [RFC2971 - Formal Syntax](https://tools.ietf.org/html/rfc2971#section-4)
#[allow(clippy::type_complexity)]
fn id_param(i: &[u8]) -> IResult<&[u8], (Cow<'_, str>, Option<Cow<'_, str>>)> {
    separated_pair(string_utf8, space1, nstring_utf8).parse(i)
}

// The non-nil case of id parameter list.
// Format: "(" #(string SPACE nstring) ")"
// [RFC2971 - Formal Syntax](https://tools.ietf.org/html/rfc2971#section-4)
fn id_param_list_not_nil(i: &[u8]) -> IResult<&[u8], HashMap<Cow<'_, str>, Cow<'_, str>>> {
    map(
        (
            char('('),
            id_param,
            many0((space1, id_param)),
            preceded(space0, char(')')),
        ),
        |(_, first_param, rest_params, _)| {
            let mut params = vec![first_param];
            for (_, p) in rest_params {
                params.push(p)
            }

            params
                .into_iter()
                .filter(|(_k, v)| v.is_some())
                .map(|(k, v)| (k, v.unwrap()))
                .collect()
        },
    )
    .parse(i)
}

// The id parameter list of all cases
// id_params_list ::= "(" #(string SPACE nstring) ")" / nil
// [RFC2971 - Formal Syntax](https://tools.ietf.org/html/rfc2971#section-4)
#[allow(clippy::type_complexity)]
fn id_param_list(i: &[u8]) -> IResult<&[u8], Option<HashMap<Cow<'_, str>, Cow<'_, str>>>> {
    alt((map(id_param_list_not_nil, Some), map(nil, |_| None))).parse(i)
}

// id_response ::= "ID" SPACE id_params_list
// [RFC2971 - Formal Syntax](https://tools.ietf.org/html/rfc2971#section-4)
pub(crate) fn resp_id(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    let (rest, map) = map(
        (tag_no_case("ID"), space1, id_param_list),
        |(_id, _sp, p)| p,
    )
    .parse(i)?;

    Ok((rest, Response::Id(map)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn test_id_param() {
        assert_matches!(
            id_param(br#""name" "Cyrus""#),
            Ok((_, (name, value))) => {
                assert_eq!(name, "name");
                assert_eq!(value.as_deref(), Some("Cyrus"));
            }
        );

        assert_matches!(
            id_param(br#""name" NIL"#),
            Ok((_, (name, value))) => {
                assert_eq!(name, "name");
                assert!(value.is_none());
            }
        );
    }

    #[test]
    fn test_id_param_list_not_nil() {
        assert_matches!(
            id_param_list_not_nil(br#"("name" "Cyrus" "version" "1.5" "os" "sunos" "os-version" "5.5" "support-url" "mailto:cyrus-bugs+@andrew.cmu.edu")"#),
            Ok((_, params)) => {
                assert_eq!(
                    params,
                    vec![
                        ("name", "Cyrus"),
                        ("version", "1.5"),
                        ("os", "sunos"),
                        ("os-version", "5.5"),
                        ("support-url", "mailto:cyrus-bugs+@andrew.cmu.edu"),
                    ].into_iter()
                    .map(|(k, v)| (Cow::Borrowed(k), Cow::Borrowed(v)))
                    .collect()
                );
            }
        );
    }

    #[test]
    fn test_id_param_list() {
        assert_matches!(
            id_param_list(br#"("name" "Cyrus" "version" "1.5" "os" "sunos" "os-version" "5.5" "support-url" "mailto:cyrus-bugs+@andrew.cmu.edu")"#),
            Ok((_, Some(params))) => {
                assert_eq!(
                    params,
                    vec![
                        ("name", "Cyrus"),
                        ("version", "1.5"),
                        ("os", "sunos"),
                        ("os-version", "5.5"),
                        ("support-url", "mailto:cyrus-bugs+@andrew.cmu.edu"),
                    ].into_iter()
                    .map(|(k, v)| (Cow::Borrowed(k), Cow::Borrowed(v)))
                    .collect()
                );
            }
        );

        assert_matches!(
            id_param_list(br##"NIL"##),
            Ok((_, params)) => {
                assert_eq!(params, None);
            }
        );
    }

    #[test]
    fn test_resp_id() {
        assert_matches!(
            resp_id(br#"ID ("name" "Cyrus" "version" "1.5" "os" "sunos" "os-version" "5.5" "support-url" "mailto:cyrus-bugs+@andrew.cmu.edu")"#),
            Ok((_, Response::Id(Some(id_info)))) => {
                assert_eq!(
                    id_info,
                    vec![
                        ("name", "Cyrus"),
                        ("version", "1.5"),
                        ("os", "sunos"),
                        ("os-version", "5.5"),
                        ("support-url", "mailto:cyrus-bugs+@andrew.cmu.edu"),
                    ].into_iter()
                    .map(|(k, v)| (Cow::Borrowed(k), Cow::Borrowed(v)))
                    .collect()
                );
            }
        );

        // Test that NILs inside parameter list don't crash the parser.
        // RFC2971 allows NILs as parameter values.
        assert_matches!(
            resp_id(br#"ID ("name" "Cyrus" "version" "1.5" "os" NIL "os-version" NIL "support-url" "mailto:cyrus-bugs+@andrew.cmu.edu")"#),
            Ok((_, Response::Id(Some(id_info)))) => {
                assert_eq!(
                    id_info,
                    vec![
                        ("name", "Cyrus"),
                        ("version", "1.5"),
                        ("support-url", "mailto:cyrus-bugs+@andrew.cmu.edu"),
                    ].into_iter()
                    .map(|(k, v)| (Cow::Borrowed(k), Cow::Borrowed(v)))
                    .collect()
                );
            }
        );

        assert_matches!(
            resp_id(br##"ID NIL"##),
            Ok((_, Response::Id(id_info))) => {
                assert_eq!(id_info, None);
            }
        );

        assert_matches!(
            resp_id(br#"ID ("name" "Archiveopteryx" "version" "3.2.0" "compile-time" "Feb  6 2023 19:59:14" "homepage-url" "http://archiveopteryx.org" "release-url" "http://archiveopteryx.org/3.2.0" )"#),
            Ok((_, Response::Id(Some(id_info)))) => {
                assert_eq!(
                    id_info,
                    vec![
                        ("name", "Archiveopteryx"),
                        ("version", "3.2.0"),
                        ("compile-time", "Feb  6 2023 19:59:14"),
                        ("homepage-url", "http://archiveopteryx.org"),
                        ("release-url", "http://archiveopteryx.org/3.2.0"),
                    ].into_iter()
                    .map(|(k, v)| (Cow::Borrowed(k), Cow::Borrowed(v)))
                    .collect()
                );
            }
        );
    }
}
