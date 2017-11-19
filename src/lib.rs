#[macro_use]
extern crate nom;

pub trait FromByteResponse<'a> {
    fn from_bytes(&'a [u8]) -> Self;
}

impl<'a> FromByteResponse<'a> for &'a str {
    fn from_bytes(b: &'a [u8]) -> Self {
        use std;
        std::str::from_utf8(b).unwrap()
    }
}

impl<'a> FromByteResponse<'a> for &'a [u8] {
    fn from_bytes(b: &'a [u8]) -> Self {
        b
    }
}

pub mod builders;
mod parser;
pub mod types;

pub use parser::ParseResult;
pub use parser::{parse_response, parse_response_raw, parse_response_str};
pub use types::*;
