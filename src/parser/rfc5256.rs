//!
//! https://tools.ietf.org/html/rfc5256
//!
//! SORT extension
//!

use nom::{
    bytes::streaming::{tag, tag_no_case},
    combinator::{map, opt},
    multi::many0,
    sequence::{preceded, terminated},
    IResult, Parser,
};

use crate::parser::{core::number, rfc3501::MailboxDatum};

/// BASE.7.2.SORT. SORT Response
///
/// Data:       zero or more numbers
///
/// The SORT response occurs as a result of a SORT or UID SORT
/// command.  The number(s) refer to those messages that match the
/// search criteria.  For SORT, these are message sequence numbers;
/// for UID SORT, these are unique identifiers.  Each number is
/// delimited by a space.
///
/// Example:
///
/// ```ignore
///     S: * SORT 2 3 6
/// ```
///
/// [RFC5256 - 4 Additional Responses](https://tools.ietf.org/html/rfc5256#section-4)
pub(crate) fn mailbox_data_sort(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(
        // Technically, trailing whitespace is not allowed for the SEARCH command,
        // but multiple email servers in the wild seem to have it anyway (see #34, #108).
        // Since the SORT command extends the SEARCH command, the trailing whitespace
        // is exceptionnaly allowed here (as for the SEARCH command).
        terminated(
            preceded(tag_no_case("SORT"), many0(preceded(tag(" "), number))),
            opt(tag(" ")),
        ),
        MailboxDatum::Sort,
    )
    .parse(i)
}
