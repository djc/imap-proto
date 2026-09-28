//!
//! https://tools.ietf.org/html/rfc4551
//!
//! IMAP Extension for Conditional STORE Operation
//! or Quick Flag Changes Resynchronization
//!

use nom::{bytes::streaming::tag_no_case, IResult, Parser};

use crate::parser::{
    core::{number_64, paren_delimited},
    rfc3501::{AttributeValue, ResponseCode, StatusAttribute},
};

// The highest mod-sequence value of all messages in the mailbox.
// Extends resp-test-code defined in rfc3501.
// [RFC4551 - 3.6 HIGHESTMODSEQ Status Data Items](https://tools.ietf.org/html/rfc4551#section-3.6)
// [RFC4551 - 4. Formal Syntax - resp-text-code](https://tools.ietf.org/html/rfc4551#section-4)
pub(crate) fn resp_text_code_highest_mod_seq(i: &[u8]) -> IResult<&[u8], ResponseCode<'_>> {
    let (i, (_, num)) = (tag_no_case("HIGHESTMODSEQ "), number_64).parse(i)?;
    Ok((i, ResponseCode::HighestModSeq(num)))
}

// Extends status-att/status-att-list defined in rfc3501
// [RFC4551 - 3.6 - HIGHESTMODSEQ Status Data Items](https://tools.ietf.org/html/rfc4551#section-3.6)
// [RFC4551 - 4. Formal Syntax - status-att-val](https://tools.ietf.org/html/rfc4551#section-4)
pub(crate) fn status_att_val_highest_mod_seq(i: &[u8]) -> IResult<&[u8], StatusAttribute> {
    let (i, (_, num)) = (tag_no_case("HIGHESTMODSEQ "), number_64).parse(i)?;
    Ok((i, StatusAttribute::HighestModSeq(num)))
}

// [RFC4551 - 4. Formal Syntax - fetch-mod-resp](https://tools.ietf.org/html/rfc4551#section-4)
pub(crate) fn msg_att_mod_seq(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    let (i, (_, num)) = (tag_no_case("MODSEQ "), paren_delimited(number_64)).parse(i)?;
    Ok((i, AttributeValue::ModSeq(num)))
}
