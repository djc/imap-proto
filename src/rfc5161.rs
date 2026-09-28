//!
//! <https://tools.ietf.org/html/rfc5161>
//!
//! The IMAP ENABLE Extension
//!

use nom::{
    bytes::streaming::tag_no_case, character::streaming::char, combinator::map, multi::many0,
    sequence::preceded, IResult, Parser,
};
use std::borrow::Cow;

use crate::core::atom;
use crate::rfc3501::Capability;
use crate::Response;

// The ENABLED response lists capabilities that were enabled in response
// to a ENABLE command.
// [RFC5161 - 3.2 The ENABLED Response](https://tools.ietf.org/html/rfc5161#section-3.2)
pub(crate) fn resp_enabled(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    map(enabled_data, Response::Capabilities).parse(i)
}

fn enabled_data(i: &[u8]) -> IResult<&[u8], Vec<Capability<'_>>> {
    let (i, (_, capabilities)) = (
        tag_no_case("ENABLED"),
        many0(preceded(char(' '), capability)),
    )
        .parse(i)?;
    Ok((i, capabilities))
}

fn capability(i: &[u8]) -> IResult<&[u8], Capability<'_>> {
    map(map(atom, Cow::Borrowed), Capability::Atom).parse(i)
}
