use nom::{
    branch::alt,
    bytes::streaming::{escaped, tag, tag_no_case, take, take_while, take_while1},
    character::streaming::{char, digit1, one_of, space0},
    combinator::{map, map_res, opt, peek},
    multi::{separated_list0, separated_list1},
    sequence::{delimited, preceded},
    IResult, Parser,
};

use std::borrow::Cow;
use std::str::{from_utf8, FromStr};

pub(crate) fn to_owned_cow<T: ?Sized + ToOwned>(c: Cow<'_, T>) -> Cow<'static, T> {
    Cow::Owned(c.into_owned())
}

// ----- number -----

// number          = 1*DIGIT
//                    ; Unsigned 32-bit integer
//                    ; (0 <= n < 4,294,967,296)
pub fn number(i: &[u8]) -> IResult<&[u8], u32> {
    let (i, bytes) = digit1(i)?;
    match from_utf8(bytes).ok().and_then(|s| u32::from_str(s).ok()) {
        Some(v) => Ok((i, v)),
        None => Err(nom::Err::Error(nom::error::make_error(
            i,
            nom::error::ErrorKind::MapRes,
        ))),
    }
}

// same as `number` but 64-bit
pub fn number_64(i: &[u8]) -> IResult<&[u8], u64> {
    let (i, bytes) = digit1(i)?;
    match from_utf8(bytes).ok().and_then(|s| u64::from_str(s).ok()) {
        Some(v) => Ok((i, v)),
        None => Err(nom::Err::Error(nom::error::make_error(
            i,
            nom::error::ErrorKind::MapRes,
        ))),
    }
}

// seq-range       = seq-number ":" seq-number
//                    ; two seq-number values and all values between
//                    ; these two regardless of order.
//                    ; seq-number is a nz-number
pub fn sequence_range(i: &[u8]) -> IResult<&[u8], std::ops::RangeInclusive<u32>> {
    map((number, tag(":"), number), |(s, _, e)| s..=e).parse(i)
}

// sequence-set    = (seq-number / seq-range) *("," sequence-set)
//                     ; set of seq-number values, regardless of order.
//                     ; Servers MAY coalesce overlaps and/or execute the
//                     ; sequence in any order.
pub fn sequence_set(i: &[u8]) -> IResult<&[u8], Vec<std::ops::RangeInclusive<u32>>> {
    separated_list1(tag(","), alt((sequence_range, map(number, |n| n..=n)))).parse(i)
}

// ----- string -----

// string = quoted / literal
pub fn string(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    alt((quoted, map(literal, Cow::Borrowed))).parse(i)
}

#[inline]
fn lossy_str<'a>(bytes: impl Into<Cow<'a, [u8]>>) -> Cow<'a, str> {
    match bytes.into() {
        Cow::Borrowed(bytes) => String::from_utf8_lossy(bytes),
        Cow::Owned(bytes) => match String::from_utf8(bytes) {
            Ok(text) => Cow::Owned(text),
            Err(error) => Cow::Owned(String::from_utf8_lossy(error.as_bytes()).into_owned()),
        },
    }
}

// string bytes as utf8 — falls back to lossy decoding when the literal
// or quoted contents include non-UTF-8 bytes (e.g. Latin-1 / ISO-8859-9
// MIME filenames in BODYSTRUCTURE responses). Strict from_utf8 would
// fail, breaking the entire response stream on a single bad mail.
pub fn string_utf8(i: &[u8]) -> IResult<&[u8], Cow<'_, str>> {
    map(string, lossy_str).parse(i)
}

// quoted = DQUOTE *QUOTED-CHAR DQUOTE
pub fn quoted(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    map_res(
        delimited(
            char('"'),
            alt((
                // nom 8's `escaped` rejects empty input, so match an empty quoted string separately.
                map(peek(char('"')), |_| &b""[..]),
                escaped(
                    take_while1(|byte| is_text_char(byte) && !is_quoted_specials(byte)),
                    '\\',
                    one_of("\\\""),
                ),
            )),
            char('"'),
        ),
        unescape,
    )
    .parse(i)
}

// QUOTED-CHAR = <any TEXT-CHAR except quoted-specials> / "\" quoted-specials
fn unescape(bytes: &[u8]) -> Result<Cow<'_, [u8]>, ()> {
    if !bytes.contains(&b'\\') {
        return Ok(Cow::Borrowed(bytes));
    }

    let mut unescaped = Vec::with_capacity(bytes.len());
    let mut escaping = false;
    for &byte in bytes {
        match (escaping, byte) {
            (false, b'\\') => escaping = true,
            (false, _) => unescaped.push(byte),
            (true, b'\\' | b'"') => {
                unescaped.push(byte);
                escaping = false;
            }
            (true, _) => return Err(()),
        }
    }

    if escaping {
        return Err(());
    }
    Ok(Cow::Owned(unescaped))
}

// quoted bytes as utf8 — lossy, see comment on string_utf8.
pub fn quoted_utf8(i: &[u8]) -> IResult<&[u8], Cow<'_, str>> {
    map(quoted, lossy_str).parse(i)
}

// quoted-specials = DQUOTE / "\"
pub fn is_quoted_specials(c: u8) -> bool {
    c == b'"' || c == b'\\'
}

/// literal = "{" number "}" CRLF *CHAR8
///            ; Number represents the number of CHAR8s
pub fn literal(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let mut parser = (tag("{"), number, tag("}"), tag("\r\n"));

    let (remaining, (_, count, _, _)) = parser.parse(input)?;

    let (remaining, data) = take(count)(remaining)?;

    Ok((remaining, data))
}

// ----- astring ----- atom (roughly) or string

// astring = 1*ASTRING-CHAR / string
pub fn astring(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    alt((map(take_while1(is_astring_char), Cow::Borrowed), string)).parse(i)
}

// astring bytes as utf8 — lossy, see comment on string_utf8.
pub fn astring_utf8(i: &[u8]) -> IResult<&[u8], Cow<'_, str>> {
    map(astring, lossy_str).parse(i)
}

// ASTRING-CHAR = ATOM-CHAR / resp-specials
pub fn is_astring_char(c: u8) -> bool {
    is_atom_char(c) || is_resp_specials(c)
}

// ATOM-CHAR = <any CHAR except atom-specials>
pub fn is_atom_char(c: u8) -> bool {
    is_char(c) && !is_atom_specials(c)
}

// atom-specials = "(" / ")" / "{" / SP / CTL / list-wildcards / quoted-specials / resp-specials
pub fn is_atom_specials(c: u8) -> bool {
    c == b'('
        || c == b')'
        || c == b'{'
        || c == b' '
        || c < 32
        || is_list_wildcards(c)
        || is_quoted_specials(c)
        || is_resp_specials(c)
}

// resp-specials = "]"
pub fn is_resp_specials(c: u8) -> bool {
    c == b']'
}

// atom = 1*ATOM-CHAR
pub fn atom(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while1(is_atom_char), from_utf8).parse(i)
}

// ----- nstring ----- nil or string

// nstring = string / nil
pub fn nstring(i: &[u8]) -> IResult<&[u8], Option<Cow<'_, [u8]>>> {
    alt((map(nil, |_| None), map(string, Some))).parse(i)
}

// nstring bytes as utf8 — lossy, see comment on string_utf8.
pub fn nstring_utf8(i: &[u8]) -> IResult<&[u8], Option<Cow<'_, str>>> {
    alt((map(nil, |_| None), map(string_utf8, Some))).parse(i)
}

// nil = "NIL"
pub fn nil(i: &[u8]) -> IResult<&[u8], &[u8]> {
    tag_no_case("NIL")(i)
}

// ----- text -----

// text = 1*TEXT-CHAR — lossy, see comment on string_utf8.
pub fn text(i: &[u8]) -> IResult<&[u8], Cow<'_, str>> {
    map(take_while(is_text_char), lossy_str).parse(i)
}

// TEXT-CHAR = <any CHAR except CR and LF>
pub fn is_text_char(c: u8) -> bool {
    is_char(c) && c != b'\r' && c != b'\n'
}

// CHAR = %x01-7F
//          ; any 7-bit US-ASCII character,
//          ;  excluding NUL
// From RFC5234
//
// Real-world IMAP servers (Dovecot, Cyrus, …) regularly emit 8-bit bytes
// inside quoted strings and literals — typically MIME filenames in
// non-UTF-8 encodings like Latin-1 or ISO-8859-9 (Turkish). RFC 6855 /
// IMAP4rev2 (RFC 9051) formally allow UTF-8 in these positions. Strict
// 7-bit rejection breaks BODYSTRUCTURE parsing on a single bad mail and
// desyncs the entire stream. Accept any non-NUL byte and let the
// higher-level UTF-8 conversion deal with non-UTF-8 sequences via lossy
// decoding.
pub fn is_char(c: u8) -> bool {
    c != 0
}

// ----- others -----

// list-wildcards = "%" / "*"
pub fn is_list_wildcards(c: u8) -> bool {
    c == b'%' || c == b'*'
}

pub fn paren_delimited<'a, O, E>(
    f: impl Parser<&'a [u8], Output = O, Error = E>,
) -> impl Parser<&'a [u8], Output = O, Error = E>
where
    E: nom::error::ParseError<&'a [u8]>,
{
    delimited(char('('), f, char(')'))
}

pub fn parenthesized_nonempty_list<'a, O, E>(
    f: impl Parser<&'a [u8], Output = O, Error = E>,
) -> impl Parser<&'a [u8], Output = Vec<O>, Error = E>
where
    E: nom::error::ParseError<&'a [u8]>,
{
    delimited(
        char('('),
        separated_list1(char(' '), f),
        // Targeted lenience: Some real-world IMAP servers
        // insert extra whitespace before the closing parenthesis.
        (space0, char(')')),
    )
}

pub fn parenthesized_list<'a, O, E>(
    f: impl Parser<&'a [u8], Output = O, Error = E>,
) -> impl Parser<&'a [u8], Output = Vec<O>, Error = E>
where
    E: nom::error::ParseError<&'a [u8]>,
{
    delimited(
        char('('),
        separated_list0(char(' '), f),
        preceded(
            opt(char(' ')), // Surgemail sometimes sends a space before the closing bracket.
            char(')'),
        ),
    )
}

pub fn opt_opt<'a, O, E>(
    mut f: impl Parser<&'a [u8], Output = Option<O>, Error = E>,
) -> impl Parser<&'a [u8], Output = Option<O>, Error = E>
where
    E: nom::error::ParseError<&'a [u8]>,
{
    move |i: &'a [u8]| match f.parse(i) {
        Ok((i, o)) => Ok((i, o)),
        Err(nom::Err::Error(_)) => Ok((i, None)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn test_quoted() {
        let (rem, val) = quoted(br#""Hello"???"#).unwrap();
        assert_eq!(rem, b"???");
        assert_eq!(val, &b"Hello"[..]);
        assert_matches!(val, Cow::Borrowed(_));

        let (rem, val) = quoted(br#"""???"#).unwrap();
        assert_eq!(rem, b"???");
        assert_matches!(val, Cow::Borrowed(b""));

        // Allowed escapes...
        assert_eq!(
            quoted(br#""Hello \" "???"#),
            Ok((&b"???"[..], Cow::Owned(br#"Hello " "#.to_vec())))
        );
        assert_eq!(
            quoted(br#""Hello \\ "???"#),
            Ok((&b"???"[..], Cow::Owned(br#"Hello \ "#.to_vec())))
        );
        assert_eq!(
            quoted(br#""a\\"???"#),
            Ok((&b"???"[..], Cow::Owned(br#"a\"#.to_vec())))
        );
        assert_eq!(
            quoted(br#""\\\"\\"???"#),
            Ok((&b"???"[..], Cow::Owned(br#"\"\"#.to_vec())))
        );

        // Not allowed escapes...
        assert!(quoted(br#""Hello \a "???"#).is_err());
        assert!(quoted(br#""Hello \z "???"#).is_err());
        assert!(quoted(br#""Hello \? "???"#).is_err());

        let (rem, val) = quoted(br#""Hello \"World\""???"#).unwrap();
        assert_eq!(rem, br#"???"#);
        assert_eq!(val, &br#"Hello "World""#[..]);

        // Test Incomplete
        assert_matches!(quoted(br#""#), Err(nom::Err::Incomplete(_)));
        assert_matches!(quoted(br#""\"#), Err(nom::Err::Incomplete(_)));
        assert_matches!(quoted(br#""Hello "#), Err(nom::Err::Incomplete(_)));

        // Test Error
        assert_matches!(quoted(br"\"), Err(nom::Err::Error(_)));
    }

    #[test]
    fn test_quoted_with_escape_and_non_utf8_byte() {
        let input = b"\"caf\xe9 \\\"\"???";
        assert_eq!(
            quoted(input),
            Ok((&b"???"[..], Cow::Owned(b"caf\xe9 \"".to_vec())))
        );
        assert_eq!(
            quoted_utf8(input),
            Ok((&b"???"[..], Cow::Owned("caf\u{FFFD} \"".to_owned())))
        );
    }

    #[test]
    fn test_unescape_rejects_invalid_escapes() {
        assert_eq!(unescape(br"\a"), Err(()));
        assert_eq!(unescape(br"a\"), Err(()));
    }

    #[test]
    fn test_string_literal() {
        match string(b"{3}\r\nXYZ") {
            Ok((_, value)) => {
                assert_eq!(value, &b"XYZ"[..]);
            }
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_string_literal_containing_null() {
        match string(b"{5}\r\nX\0Y\0Z") {
            Ok((_, value)) => {
                assert_eq!(value, &b"X\0Y\0Z"[..]);
            }
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_astring() {
        match astring(b"text ") {
            Ok((_, value)) => {
                assert_eq!(value, &b"text"[..]);
            }
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_sequence_range() {
        match sequence_range(b"23:28 ") {
            Ok((_, value)) => {
                assert_eq!(*value.start(), 23);
                assert_eq!(*value.end(), 28);
                assert_eq!(value.collect::<Vec<u32>>(), vec![23, 24, 25, 26, 27, 28]);
            }
            rsp => panic!("Unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_sequence_set() {
        match sequence_set(b"1,2:8,10,15:30 ") {
            Ok((_, value)) => {
                assert_eq!(value.len(), 4);
                let v = &value[0];
                assert_eq!(*v.start(), 1);
                assert_eq!(*v.end(), 1);
                let v = &value[1];
                assert_eq!(*v.start(), 2);
                assert_eq!(*v.end(), 8);
                let v = &value[2];
                assert_eq!(*v.start(), 10);
                assert_eq!(*v.end(), 10);
                let v = &value[3];
                assert_eq!(*v.start(), 15);
                assert_eq!(*v.end(), 30);
            }
            rsp => panic!("Unexpected response {rsp:?}"),
        }
    }
}
