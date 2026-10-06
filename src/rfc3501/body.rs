use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    character::streaming::char,
    combinator::{map, opt},
    multi::many0,
    sequence::{delimited, preceded},
    IResult, Parser,
};

use crate::core::*;
use crate::rfc3501::AttributeValue;

pub fn section_part(i: &[u8]) -> IResult<&[u8], Vec<u32>> {
    let (i, (part, mut rest)) = (number, many0(preceded(char('.'), number))).parse(i)?;
    rest.insert(0, part);
    Ok((i, rest))
}

pub fn section_msgtext(i: &[u8]) -> IResult<&[u8], MessageSection> {
    alt((
        map(
            (
                tag_no_case("HEADER.FIELDS"),
                opt(tag_no_case(".NOT")),
                tag(" "),
                parenthesized_list(astring),
            ),
            |_| MessageSection::Header,
        ),
        map(tag_no_case("HEADER"), |_| MessageSection::Header),
        map(tag_no_case("TEXT"), |_| MessageSection::Text),
    ))
    .parse(i)
}

#[derive(Debug, Eq, PartialEq)]
pub enum MessageSection {
    Header,
    Mime,
    Text,
}

impl MessageSection {
    pub fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        alt((
            section_msgtext,
            map(tag_no_case("MIME"), |_| MessageSection::Mime),
        ))
        .parse(i)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SectionPath {
    Full(MessageSection),
    Part(Vec<u32>, Option<MessageSection>),
}

impl SectionPath {
    pub fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        alt((
            map(section_msgtext, SectionPath::Full),
            map(
                (
                    section_part,
                    opt(preceded(char('.'), MessageSection::parse)),
                ),
                |(part, text)| SectionPath::Part(part, text),
            ),
        ))
        .parse(i)
    }
}

pub fn section(i: &[u8]) -> IResult<&[u8], Option<SectionPath>> {
    delimited(char('['), opt(SectionPath::parse), char(']')).parse(i)
}

pub fn msg_att_body_section(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(
        (
            tag_no_case("BODY"),
            section,
            opt(delimited(char('<'), number, char('>'))),
            tag(" "),
            nstring,
        ),
        |(_, section, index, _, data)| AttributeValue::BodySection {
            section,
            index,
            data,
        },
    )
    .parse(i)
}
