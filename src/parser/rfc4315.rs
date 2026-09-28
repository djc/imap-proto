//!
//! https://tools.ietf.org/html/rfc4315
//!
//! The IMAP UIDPLUS Extension
//!

use std::ops::RangeInclusive;

use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    combinator::map,
    multi::separated_list1,
    sequence::preceded,
    IResult, Parser,
};

use crate::parser::core::number;
use crate::parser::rfc3501::ResponseCode;

/// Extends resp-text-code as follows:
///
/// ```ignore
///     resp-text-code =/ resp-code-apnd
///     resp-code-apnd = "APPENDUID" SP nz-number SP append-uid
///     append-uid      =/ uid-set
///                       ; only permitted if client uses [MULTIAPPEND]
///                       ; to append multiple messages.
/// ```
///
/// [RFC4315 - 3 Additional Response Codes](https://tools.ietf.org/html/rfc4315#section-3)
pub(crate) fn resp_text_code_append_uid(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(
        preceded(tag_no_case("APPENDUID "), (number, tag(" "), uid_set)),
        |(fst, _, snd)| ResponseCode::AppendUid(fst, snd),
    )
    .parse(i)
}

/// Extends resp-text-code as follows:
///
/// ```ignore
///     resp-text-code =/ resp-code-copy
///     resp-code-copy = "COPYUID" SP nz-number SP uid-set
/// ```
///
/// [RFC4315 - 3 Additional Response Codes](https://tools.ietf.org/html/rfc4315#section-3)
pub(crate) fn resp_text_code_copy_uid(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(
        preceded(
            tag_no_case("COPYUID "),
            (number, tag(" "), uid_set, tag(" "), uid_set),
        ),
        |(fst, _, snd, _, trd)| ResponseCode::CopyUid(fst, snd, trd),
    )
    .parse(i)
}

/// Extends resp-text-code as follows:
///
/// ```ignore
///     resp-text-code =/ "UIDNOTSTICKY"
/// ```
///
/// [RFC4315 - 3 Additional Response Codes](https://tools.ietf.org/html/rfc4315#section-3)
pub(crate) fn resp_text_code_uid_not_sticky(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    map(tag_no_case("UIDNOTSTICKY"), |_| ResponseCode::UidNotSticky).parse(i)
}

/// Parses the uid-set nonterminal:
///
/// ```ignore
///     uid-set = (uniqueid / uid-range) *("," uid-set)
/// ```
///
/// [RFC4315 - 4 Formal Syntax](https://tools.ietf.org/html/rfc4315#section-4)
fn uid_set(i: &[u8]) -> IResult<&[u8], Vec<UidSetMember>> {
    separated_list1(tag(","), UidSetMember::parse).parse(i)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UidSetMember {
    UidRange(RangeInclusive<u32>),
    Uid(u32),
}

impl UidSetMember {
    // uid-set member: uniqueid / uid-range
    fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        alt((uid_range, map(number, From::from))).parse(i)
    }
}

impl From<RangeInclusive<u32>> for UidSetMember {
    fn from(x: RangeInclusive<u32>) -> Self {
        UidSetMember::UidRange(x)
    }
}

impl From<u32> for UidSetMember {
    fn from(x: u32) -> Self {
        UidSetMember::Uid(x)
    }
}

/// Parses the uid-set nonterminal:
///
/// ```ignore
///    uid-range = (uniqueid ":" uniqueid)
///                ; two uniqueid values and all values
///                ; between these two regards of order.
///                ; Example: 2:4 and 4:2 are equivalent.
/// ```
///
/// [RFC4315 - 4 Formal Syntax](https://tools.ietf.org/html/rfc4315#section-4)
fn uid_range(i: &[u8]) -> IResult<&[u8], UidSetMember> {
    map(
        nom::sequence::separated_pair(number, tag(":"), number),
        |(fst, snd)| if fst <= snd { fst..=snd } else { snd..=fst }.into(),
    )
    .parse(i)
}
