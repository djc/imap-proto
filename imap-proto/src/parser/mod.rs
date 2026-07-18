use crate::types::Response;
use nom::{branch::alt, IResult};

pub mod core;

pub mod bodystructure;
pub mod gmail;
pub mod rfc2087;
pub mod rfc2971;
pub mod rfc3501;
pub mod rfc4314;
pub mod rfc4315;
pub mod rfc4551;
pub mod rfc5161;
pub mod rfc5256;
pub mod rfc5464;
pub mod rfc7162;

#[cfg(test)]
mod tests;

pub fn parse_response(msg: &[u8]) -> ParseResult<'_> {
    alt((
        rfc3501::continue_req,
        rfc3501::response_data,
        rfc3501::response_tagged,
    ))(msg)
}

/// Parse a response while preserving RFC 5161 `ENABLED` responses as a
/// distinct [`Response::Enabled`] variant.
///
/// [`parse_response`] retains its historical behavior and represents both
/// `CAPABILITY` and `ENABLED` response data as [`Response::Capabilities`].
pub fn parse_response_with_enabled(msg: &[u8]) -> ParseResult<'_> {
    alt((
        rfc3501::continue_req,
        rfc3501::response_data_with_enabled,
        rfc3501::response_tagged,
    ))(msg)
}

pub type ParseResult<'a> = IResult<&'a [u8], Response<'a>>;
