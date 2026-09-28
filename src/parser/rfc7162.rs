//!
//!
//! https://tools.ietf.org/html/rfc7162
//!
//! The IMAP QRESYNC Extensions
//!

use nom::{
    bytes::streaming::tag_no_case, character::streaming::space1, combinator::opt, IResult, Parser,
};

use crate::parser::core::sequence_set;
use crate::types::*;

// The VANISHED response reports that the specified UIDs have been
// permanently removed from the mailbox.  This response is similar to
// the EXPUNGE response (RFC3501); however, it can return information
// about multiple messages, and it returns UIDs instead of message
// numbers.
// [RFC7162 - VANISHED RESPONSE](https://tools.ietf.org/html/rfc7162#section-3.2.10)
pub(crate) fn resp_vanished(i: &[u8]) -> IResult<&[u8], Response<'_>> {
    let (rest, (_, earlier, _, uids)) = (
        tag_no_case("VANISHED"),
        opt((space1, tag_no_case("(EARLIER)"))),
        space1,
        sequence_set,
    )
        .parse(i)?;
    Ok((
        rest,
        Response::Vanished {
            earlier: earlier.is_some(),
            uids,
        },
    ))
}
