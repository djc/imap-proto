use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    character::streaming::{char, space0},
    combinator::{map, opt},
    error::{Error, ErrorKind},
    sequence::{delimited, preceded},
    IResult, Parser,
};
use std::borrow::Cow;

use crate::{
    core::*,
    rfc3501::{to_owned_cow, AttributeValue, Envelope},
};

/// Deepest nesting the parser accepts, counted separately for body parts
/// (multipart and `message/rfc822` levels) and for body-extension lists.
///
/// Parsing itself does not use the call stack for nesting, but the parsed
/// types are recursive and so are their drop glue, `Debug`, `PartialEq` and
/// `into_owned`, as well as any code that walks them. Real messages nest a
/// handful of levels; this leaves ample headroom and still bounds all of that.
const MAX_NESTING_DEPTH: usize = 64;

fn too_deep<T>(i: &[u8]) -> Result<T, NomErr<'_>> {
    Err(nom::Err::Failure(Error::new(i, ErrorKind::TooLarge)))
}

// The error half of an `IResult` over byte input.
type NomErr<'a> = nom::Err<Error<&'a [u8]>>;

// A parse result with the recoverable error split out. `Miss` means this
// grammar alternative did not match and the next one may be tried; `Failure`
// and `Incomplete` abort the whole parse, which `?` on `branch` takes care of.
enum Branch<'a, O> {
    Hit(&'a [u8], O),
    Miss(NomErr<'a>),
}

fn branch<'a, O>(result: IResult<&'a [u8], O>) -> Result<Branch<'a, O>, NomErr<'a>> {
    match result {
        Ok((rest, value)) => Ok(Branch::Hit(rest, value)),
        Err(e @ nom::Err::Error(_)) => Ok(Branch::Miss(e)),
        Err(e) => Err(e),
    }
}

pub struct BodyFields<'a> {
    pub param: BodyParams<'a>,
    pub id: Option<Cow<'a, str>>,
    pub description: Option<Cow<'a, str>>,
    pub transfer_encoding: ContentEncoding<'a>,
    pub octets: u32,
}

impl<'a> BodyFields<'a> {
    // body-fields     = body-fld-param SP body-fld-id SP body-fld-desc SP
    //                   body-fld-enc SP body-fld-octets
    fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (i, (param, _, id, _, description, _, transfer_encoding, _, octets)) = (
            body_param,
            tag(" "),
            // body id seems to refer to the Message-ID or possibly Content-ID header, which
            // by the definition in RFC 2822 seems to resolve to all ASCII characters (through
            // a large amount of indirection which I did not have the patience to fully explore)
            nstring_utf8,
            tag(" "),
            // Per https://tools.ietf.org/html/rfc2045#section-8, description should be all ASCII
            nstring_utf8,
            tag(" "),
            ContentEncoding::parse,
            tag(" "),
            number,
        )
            .parse(i)?;
        Ok((
            i,
            BodyFields {
                param,
                id,
                description,
                transfer_encoding,
                octets,
            },
        ))
    }

    pub fn into_owned(self) -> BodyFields<'static> {
        BodyFields {
            param: body_param_owned(self.param),
            id: self.id.map(to_owned_cow),
            description: self.description.map(to_owned_cow),
            transfer_encoding: self.transfer_encoding.into_owned(),
            octets: self.octets,
        }
    }
}

pub struct BodyExt1Part<'a> {
    pub md5: Option<Cow<'a, str>>,
    pub disposition: Option<ContentDisposition<'a>>,
    pub language: Option<Vec<Cow<'a, str>>>,
    pub location: Option<Cow<'a, str>>,
    pub extension: Option<BodyExtension<'a>>,
}

impl<'a> BodyExt1Part<'a> {
    // body-ext-1part  = body-fld-md5 [SP body-fld-dsp [SP body-fld-lang
    //                   [SP body-fld-loc *(SP body-extension)]]]
    //                     ; MUST NOT be returned on non-extensible
    //                     ; "BODY" fetch
    fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (i, (md5, disposition, language, location, extension)) = (
            // Per RFC 1864, MD5 values are base64-encoded
            opt_opt(preceded(tag(" "), nstring_utf8)),
            opt_opt(preceded(tag(" "), body_disposition)),
            opt_opt(preceded(tag(" "), body_lang)),
            // Location appears to reference a URL, which by RFC 1738 (section 2.2) should be ASCII
            opt_opt(preceded(tag(" "), nstring_utf8)),
            opt(preceded(tag(" "), BodyExtension::parse)),
        )
            .parse(i)?;
        Ok((
            i,
            BodyExt1Part {
                md5,
                disposition,
                language,
                location,
                extension,
            },
        ))
    }

    pub fn into_owned(self) -> BodyExt1Part<'static> {
        BodyExt1Part {
            md5: self.md5.map(to_owned_cow),
            disposition: self.disposition.map(|v| v.into_owned()),
            language: self
                .language
                .map(|v| v.into_iter().map(to_owned_cow).collect()),
            location: self.location.map(to_owned_cow),
            extension: self.extension.map(|v| v.into_owned()),
        }
    }
}

pub struct BodyExtMPart<'a> {
    pub param: BodyParams<'a>,
    pub disposition: Option<ContentDisposition<'a>>,
    pub language: Option<Vec<Cow<'a, str>>>,
    pub location: Option<Cow<'a, str>>,
    pub extension: Option<BodyExtension<'a>>,
}

impl<'a> BodyExtMPart<'a> {
    // body-ext-mpart  = body-fld-param [SP body-fld-dsp [SP body-fld-lang
    //                   [SP body-fld-loc *(SP body-extension)]]]
    //                     ; MUST NOT be returned on non-extensible
    //                     ; "BODY" fetch
    fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (i, (param, disposition, language, location, extension)) = (
            opt_opt(preceded(tag(" "), body_param)),
            opt_opt(preceded(tag(" "), body_disposition)),
            opt_opt(preceded(tag(" "), body_lang)),
            // Location appears to reference a URL, which by RFC 1738 (section 2.2) should be ASCII
            opt_opt(preceded(tag(" "), nstring_utf8)),
            opt(preceded(tag(" "), BodyExtension::parse)),
        )
            .parse(i)?;
        Ok((
            i,
            BodyExtMPart {
                param,
                disposition,
                language,
                location,
                extension,
            },
        ))
    }

    pub fn into_owned(self) -> BodyExtMPart<'static> {
        BodyExtMPart {
            param: body_param_owned(self.param),
            disposition: self.disposition.map(|v| v.into_owned()),
            language: self
                .language
                .map(|v| v.into_iter().map(to_owned_cow).collect()),
            location: self.location.map(to_owned_cow),
            extension: self.extension.map(|v| v.into_owned()),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ContentEncoding<'a> {
    SevenBit,
    EightBit,
    Binary,
    Base64,
    QuotedPrintable,
    Other(Cow<'a, str>),
}

impl<'a> ContentEncoding<'a> {
    // RFC 3501 defines `body-fld-enc` as a string, never NIL, but some servers send
    // NIL for a part with no Content-Transfer-Encoding header (seen on Apple iCloud;
    // imap-codec records the same from maddy). RFC 2045 s6.1 defaults that to 7bit.
    fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        alt((
            map(nil, |_| ContentEncoding::SevenBit),
            delimited(
                char('"'),
                alt((
                    map(tag_no_case("7BIT"), |_| ContentEncoding::SevenBit),
                    map(tag_no_case("8BIT"), |_| ContentEncoding::EightBit),
                    map(tag_no_case("BINARY"), |_| ContentEncoding::Binary),
                    map(tag_no_case("BASE64"), |_| ContentEncoding::Base64),
                    map(tag_no_case("QUOTED-PRINTABLE"), |_| {
                        ContentEncoding::QuotedPrintable
                    }),
                )),
                char('"'),
            ),
            map(string_utf8, ContentEncoding::Other),
        ))
        .parse(i)
    }

    pub fn into_owned(self) -> ContentEncoding<'static> {
        match self {
            ContentEncoding::SevenBit => ContentEncoding::SevenBit,
            ContentEncoding::EightBit => ContentEncoding::EightBit,
            ContentEncoding::Binary => ContentEncoding::Binary,
            ContentEncoding::Base64 => ContentEncoding::Base64,
            ContentEncoding::QuotedPrintable => ContentEncoding::QuotedPrintable,
            ContentEncoding::Other(v) => ContentEncoding::Other(to_owned_cow(v)),
        }
    }
}

fn body_lang(i: &[u8]) -> IResult<&[u8], Option<Vec<Cow<'_, str>>>> {
    alt((
        // body language seems to refer to RFC 3066 language tags, which should be ASCII-only
        map(nstring_utf8, |v| v.map(|s| vec![s])),
        map(parenthesized_nonempty_list(string_utf8), Option::from),
    ))
    .parse(i)
}

fn body_param(i: &[u8]) -> IResult<&[u8], BodyParams<'_>> {
    alt((
        map(nil, |_| None),
        map(
            parenthesized_nonempty_list(map(
                (string_utf8, tag(" "), string_utf8),
                |(key, _, val)| (key, val),
            )),
            Option::from,
        ),
    ))
    .parse(i)
}

enum Head<'a> {
    Value(BodyExtension<'a>),
    Open,
}

#[derive(Debug, Eq, PartialEq)]
pub enum BodyExtension<'a> {
    Num(u32),
    Str(Option<Cow<'a, str>>),
    List(Vec<BodyExtension<'a>>),
}

impl<'a> BodyExtension<'a> {
    // body-extension  = nstring / number /
    //                   "(" body-extension *(SP body-extension) ")"
    //
    // Lists nest, so this keeps the open lists on the heap rather than recursing:
    // input nesting depth must not translate into call-stack depth.
    fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        let mut open: Vec<Vec<BodyExtension<'a>>> = Vec::new();
        let (mut rest, mut head) = Self::head(i)?;
        loop {
            // Descend into opening lists until a number or string is found ...
            let mut value = loop {
                match head {
                    Head::Value(value) => break value,
                    Head::Open if open.len() >= MAX_NESTING_DEPTH => return too_deep(i),
                    Head::Open => open.push(Vec::new()),
                }
                (rest, head) = Self::head(rest)?;
            };
            // ... then add it to the enclosing list, closing every list it ends.
            head = loop {
                let Some(mut list) = open.pop() else {
                    return Ok((rest, value));
                };
                list.push(value);

                // A space continues the list with its next item ...
                if let Branch::Hit(after, (_, next)) = branch((char(' '), Self::head).parse(rest))?
                {
                    open.push(list);
                    rest = after;
                    break next;
                }

                // ... anything else ends it, and the closed list becomes a value of
                // the list around it. Targeted lenience: some real-world IMAP servers
                // insert extra whitespace before the closing parenthesis.
                (rest, _) = (space0, char(')')).parse(rest)?;
                value = BodyExtension::List(list);
            };
        }
    }

    // The next number, string or list opening, without parsing into a list.
    fn head(i: &'a [u8]) -> IResult<&'a [u8], Head<'a>> {
        alt((
            map(number, |n| Head::Value(BodyExtension::Num(n))),
            // Cannot find documentation on character encoding for body extension values.
            // So far, assuming UTF-8 seems fine, please report if you run into issues here.
            map(nstring_utf8, |s| Head::Value(BodyExtension::Str(s))),
            map(char('('), |_| Head::Open),
        ))
        .parse(i)
    }

    pub fn into_owned(self) -> BodyExtension<'static> {
        match self {
            BodyExtension::Num(v) => BodyExtension::Num(v),
            BodyExtension::Str(v) => BodyExtension::Str(v.map(to_owned_cow)),
            BodyExtension::List(v) => {
                BodyExtension::List(v.into_iter().map(|v| v.into_owned()).collect())
            }
        }
    }
}

fn body_disposition(i: &[u8]) -> IResult<&[u8], Option<ContentDisposition<'_>>> {
    alt((
        map(nil, |_| None),
        paren_delimited(map(
            (string_utf8, tag(" "), body_param),
            |(ty, _, params)| Some(ContentDisposition { ty, params }),
        )),
    ))
    .parse(i)
}

fn body_type_basic(i: &[u8]) -> IResult<&[u8], BodyStructure<'_>> {
    map(
        (
            string_utf8,
            tag(" "),
            string_utf8,
            tag(" "),
            BodyFields::parse,
            BodyExt1Part::parse,
        ),
        |(ty, _, subtype, _, fields, ext)| BodyStructure::Basic {
            common: BodyContentCommon {
                ty: ContentType {
                    ty,
                    subtype,
                    params: fields.param,
                },
                disposition: ext.disposition,
                language: ext.language,
                location: ext.location,
            },
            other: BodyContentSinglePart {
                id: fields.id,
                md5: ext.md5,
                octets: fields.octets,
                description: fields.description,
                transfer_encoding: fields.transfer_encoding,
            },
            extension: ext.extension,
        },
    )
    .parse(i)
}

fn body_type_text(i: &[u8]) -> IResult<&[u8], BodyStructure<'_>> {
    map(
        (
            tag_no_case("\"TEXT\""),
            tag(" "),
            string_utf8,
            tag(" "),
            BodyFields::parse,
            tag(" "),
            number,
            BodyExt1Part::parse,
        ),
        |(_, _, subtype, _, fields, _, lines, ext)| BodyStructure::Text {
            common: BodyContentCommon {
                ty: ContentType {
                    ty: Cow::Borrowed("TEXT"),
                    subtype,
                    params: fields.param,
                },
                disposition: ext.disposition,
                language: ext.language,
                location: ext.location,
            },
            other: BodyContentSinglePart {
                id: fields.id,
                md5: ext.md5,
                octets: fields.octets,
                description: fields.description,
                transfer_encoding: fields.transfer_encoding,
            },
            lines,
            extension: ext.extension,
        },
    )
    .parse(i)
}

// body-type-msg   = media-message SP body-fields SP envelope SP body SP body-fld-lines
//
// Split around the embedded `body`, which the caller parses.
fn body_type_message_head(i: &[u8]) -> IResult<&[u8], (BodyFields<'_>, Envelope<'_>)> {
    map(
        (
            tag_no_case("\"MESSAGE\" \"RFC822\""),
            tag(" "),
            BodyFields::parse,
            tag(" "),
            Envelope::parse,
            tag(" "),
        ),
        |(_, _, fields, _, envelope, _)| (fields, envelope),
    )
    .parse(i)
}

fn body_type_message_tail<'a>(
    i: &'a [u8],
    fields: BodyFields<'a>,
    envelope: Envelope<'a>,
    body: BodyStructure<'a>,
) -> IResult<&'a [u8], BodyStructure<'a>> {
    let (i, (_, lines, ext)) = (tag(" "), number, BodyExt1Part::parse).parse(i)?;
    Ok((
        i,
        BodyStructure::Message {
            common: BodyContentCommon {
                ty: ContentType {
                    ty: Cow::Borrowed("MESSAGE"),
                    subtype: Cow::Borrowed("RFC822"),
                    params: fields.param,
                },
                disposition: ext.disposition,
                language: ext.language,
                location: ext.location,
            },
            other: BodyContentSinglePart {
                id: fields.id,
                md5: ext.md5,
                octets: fields.octets,
                description: fields.description,
                transfer_encoding: fields.transfer_encoding,
            },
            envelope,
            body: Box::new(body),
            lines,
            extension: ext.extension,
        },
    ))
}

// body-type-mpart = 1*body SP media-subtype [SP body-ext-mpart]
//
// This is the part after the `1*body`, which the caller parses.
fn body_type_multipart_tail<'a>(
    i: &'a [u8],
    bodies: Vec<BodyStructure<'a>>,
) -> IResult<&'a [u8], BodyStructure<'a>> {
    let (i, (_, subtype, ext)) = (tag(" "), string_utf8, BodyExtMPart::parse).parse(i)?;
    Ok((
        i,
        BodyStructure::Multipart {
            common: BodyContentCommon {
                ty: ContentType {
                    ty: Cow::Borrowed("MULTIPART"),
                    subtype,
                    params: ext.param,
                },
                disposition: ext.disposition,
                language: ext.language,
                location: ext.location,
            },
            bodies,
            extension: ext.extension,
        },
    ))
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub enum BodyStructure<'a> {
    Basic {
        common: BodyContentCommon<'a>,
        other: BodyContentSinglePart<'a>,
        extension: Option<BodyExtension<'a>>,
    },
    Text {
        common: BodyContentCommon<'a>,
        other: BodyContentSinglePart<'a>,
        lines: u32,
        extension: Option<BodyExtension<'a>>,
    },
    Message {
        common: BodyContentCommon<'a>,
        other: BodyContentSinglePart<'a>,
        envelope: Envelope<'a>,
        body: Box<BodyStructure<'a>>,
        lines: u32,
        extension: Option<BodyExtension<'a>>,
    },
    Multipart {
        common: BodyContentCommon<'a>,
        bodies: Vec<BodyStructure<'a>>,
        extension: Option<BodyExtension<'a>>,
    },
}

// The ")" that ends a body part whose contents have been parsed.
fn close_part<'a>(i: &'a [u8], body: BodyStructure<'a>) -> Result<Step<'a>, NomErr<'a>> {
    Ok(match branch(char(')').parse(i))? {
        Branch::Hit(rest, _) => Step::Parsed(rest, body),
        Branch::Miss(e) => Step::Failed(e),
    })
}

// A body part from its opening "(". A text or basic part is parsed whole here;
// a message/rfc822 or multipart part becomes an `OpenPart` waiting for the body
// part nested inside it, which is parsed next.
fn parse_part<'a>(i: &'a [u8], open: &mut Vec<OpenPart<'a>>) -> Result<Step<'a>, NomErr<'a>> {
    let inner = match branch(char('(').parse(i))? {
        Branch::Hit(inner, _) => inner,
        Branch::Miss(e) => return Ok(Step::Failed(e)),
    };
    if let Branch::Hit(rest, body) = branch(body_type_text(inner))? {
        return close_part(rest, body);
    }
    if let Branch::Hit(rest, (fields, envelope)) = branch(body_type_message_head(inner))? {
        if open.len() >= MAX_NESTING_DEPTH {
            return too_deep(inner);
        }
        open.push(OpenPart::Message {
            start: inner,
            fields,
            envelope,
        });
        return Ok(Step::Part(rest));
    }
    parse_basic_or_multipart(inner, open)
}

// A part's interior once text and message/rfc822 are ruled out: a basic part,
// or failing that, a multipart whose first child body starts right here.
fn parse_basic_or_multipart<'a>(
    i: &'a [u8],
    open: &mut Vec<OpenPart<'a>>,
) -> Result<Step<'a>, NomErr<'a>> {
    if let Branch::Hit(rest, body) = branch(body_type_basic(i))? {
        return close_part(rest, body);
    }
    if open.len() >= MAX_NESTING_DEPTH {
        return too_deep(i);
    }
    open.push(OpenPart::Multipart {
        bodies: Vec::new(),
        next_child: i,
    });
    Ok(Step::Part(i))
}

// A body part that has been opened but not yet completed, waiting for the body
// part nested inside it. `accept` and `reject` take that inner part's result.
#[allow(clippy::large_enum_variant)]
enum OpenPart<'a> {
    // A `message/rfc822` part waiting for its embedded body. `start` is the input
    // just after the part's "(", to resume from if the message form does not parse.
    Message {
        start: &'a [u8],
        fields: BodyFields<'a>,
        envelope: Envelope<'a>,
    },
    // A multipart part collecting its child bodies. `next_child` is the input where
    // the child currently being parsed starts.
    Multipart {
        bodies: Vec<BodyStructure<'a>>,
        next_child: &'a [u8],
    },
}

impl<'a> OpenPart<'a> {
    // The inner body part has been parsed: a message part is completed by its
    // tail, a multipart stores the child and moves on to the next one.
    fn accept(
        self,
        i: &'a [u8],
        body: BodyStructure<'a>,
        open: &mut Vec<OpenPart<'a>>,
    ) -> Result<Step<'a>, NomErr<'a>> {
        match self {
            OpenPart::Message {
                start,
                fields,
                envelope,
            } => match branch(body_type_message_tail(i, fields, envelope, body))? {
                Branch::Hit(rest, message) => close_part(rest, message),
                // Not a message part after all; reparse it as basic or multipart.
                Branch::Miss(_) => parse_basic_or_multipart(start, open),
            },
            OpenPart::Multipart { mut bodies, .. } => {
                bodies.push(body);
                open.push(OpenPart::Multipart {
                    bodies,
                    next_child: i,
                });
                Ok(Step::Part(i))
            }
        }
    }

    // The inner body part did not match. A message part backtracks, as above. A
    // multipart takes it as the end of its children: at least one child followed
    // by the multipart tail is fine, none at all fails the part.
    fn reject(self, e: NomErr<'a>, open: &mut Vec<OpenPart<'a>>) -> Result<Step<'a>, NomErr<'a>> {
        match self {
            OpenPart::Message { start, .. } => parse_basic_or_multipart(start, open),
            OpenPart::Multipart { bodies, .. } if bodies.is_empty() => Ok(Step::Failed(e)),
            OpenPart::Multipart { bodies, next_child } => {
                match branch(body_type_multipart_tail(next_child, bodies))? {
                    Branch::Hit(rest, multipart) => close_part(rest, multipart),
                    Branch::Miss(e) => Ok(Step::Failed(e)),
                }
            }
        }
    }
}

// What the loop in `BodyStructure::parse` does next: descend into a new part,
// or hand a finished part -- parsed or failed -- to the part enclosing it.
#[allow(clippy::large_enum_variant)]
enum Step<'a> {
    // Parse a body part, starting at its "(".
    Part(&'a [u8]),
    // A part was parsed; the enclosing open part continues with it.
    Parsed(&'a [u8], BodyStructure<'a>),
    // The part did not match; the enclosing open part decides what that means.
    Failed(NomErr<'a>),
}

impl<'a> BodyStructure<'a> {
    // body            = "(" (body-type-1part / body-type-mpart) ")"
    //
    // Body parts nest, so instead of recursing, parts waiting for an inner body
    // sit on a heap-allocated stack. The alternatives are tried in the order of
    // the old recursive descent: text, message/rfc822, basic, multipart --
    // including backtracking from message/rfc822 to the latter two, and ending a
    // multipart's children at the first input that is not a body part.
    pub(crate) fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        let mut open: Vec<OpenPart<'a>> = Vec::new();
        let mut step = Step::Part(i);
        loop {
            step = match step {
                Step::Part(at) => parse_part(at, &mut open)?,
                Step::Parsed(at, body) => match open.pop() {
                    None => return Ok((at, body)),
                    Some(outer) => outer.accept(at, body, &mut open)?,
                },
                Step::Failed(e) => match open.pop() {
                    None => return Err(e),
                    Some(outer) => outer.reject(e, &mut open)?,
                },
            };
        }
    }

    pub fn into_owned(self) -> BodyStructure<'static> {
        match self {
            BodyStructure::Basic {
                common,
                other,
                extension,
            } => BodyStructure::Basic {
                common: common.into_owned(),
                other: other.into_owned(),
                extension: extension.map(|v| v.into_owned()),
            },
            BodyStructure::Text {
                common,
                other,
                lines,
                extension,
            } => BodyStructure::Text {
                common: common.into_owned(),
                other: other.into_owned(),
                lines,
                extension: extension.map(|v| v.into_owned()),
            },
            BodyStructure::Message {
                common,
                other,
                envelope,
                body,
                lines,
                extension,
            } => BodyStructure::Message {
                common: common.into_owned(),
                other: other.into_owned(),
                envelope: envelope.into_owned(),
                body: Box::new(body.into_owned()),
                lines,
                extension: extension.map(|v| v.into_owned()),
            },
            BodyStructure::Multipart {
                common,
                bodies,
                extension,
            } => BodyStructure::Multipart {
                common: common.into_owned(),
                bodies: bodies.into_iter().map(|v| v.into_owned()).collect(),
                extension: extension.map(|v| v.into_owned()),
            },
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct BodyContentCommon<'a> {
    pub ty: ContentType<'a>,
    pub disposition: Option<ContentDisposition<'a>>,
    pub language: Option<Vec<Cow<'a, str>>>,
    pub location: Option<Cow<'a, str>>,
}

impl<'a> BodyContentCommon<'a> {
    pub fn into_owned(self) -> BodyContentCommon<'static> {
        BodyContentCommon {
            ty: self.ty.into_owned(),
            disposition: self.disposition.map(|v| v.into_owned()),
            language: self
                .language
                .map(|v| v.into_iter().map(to_owned_cow).collect()),
            location: self.location.map(to_owned_cow),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct BodyContentSinglePart<'a> {
    pub id: Option<Cow<'a, str>>,
    pub md5: Option<Cow<'a, str>>,
    pub description: Option<Cow<'a, str>>,
    pub transfer_encoding: ContentEncoding<'a>,
    pub octets: u32,
}

impl<'a> BodyContentSinglePart<'a> {
    pub fn into_owned(self) -> BodyContentSinglePart<'static> {
        BodyContentSinglePart {
            id: self.id.map(to_owned_cow),
            md5: self.md5.map(to_owned_cow),
            description: self.description.map(to_owned_cow),
            transfer_encoding: self.transfer_encoding.into_owned(),
            octets: self.octets,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ContentType<'a> {
    pub ty: Cow<'a, str>,
    pub subtype: Cow<'a, str>,
    pub params: BodyParams<'a>,
}

impl<'a> ContentType<'a> {
    pub fn into_owned(self) -> ContentType<'static> {
        ContentType {
            ty: to_owned_cow(self.ty),
            subtype: to_owned_cow(self.subtype),
            params: body_param_owned(self.params),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ContentDisposition<'a> {
    pub ty: Cow<'a, str>,
    pub params: BodyParams<'a>,
}

impl<'a> ContentDisposition<'a> {
    pub fn into_owned(self) -> ContentDisposition<'static> {
        ContentDisposition {
            ty: to_owned_cow(self.ty),
            params: body_param_owned(self.params),
        }
    }
}

pub type BodyParams<'a> = Option<Vec<(Cow<'a, str>, Cow<'a, str>)>>;

pub(crate) fn body_param_owned(v: BodyParams<'_>) -> BodyParams<'static> {
    v.map(|v| {
        v.into_iter()
            .map(|(k, v)| (to_owned_cow(k), to_owned_cow(v)))
            .collect()
    })
}

pub(crate) fn msg_att_body_structure(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(
        (tag_no_case("BODYSTRUCTURE "), BodyStructure::parse),
        |(_, body)| AttributeValue::BodyStructure(body),
    )
    .parse(i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    const EMPTY: &[u8] = &[];

    // body-fld-param SP body-fld-id SP body-fld-desc SP body-fld-enc SP body-fld-octets
    const BODY_FIELDS: &str = r#"("foo" "bar") "id" "desc" "7BIT" 1337"#;
    const BODY_FIELD_PARAM_PAIR: (Cow<'_, str>, Cow<'_, str>) =
        (Cow::Borrowed("foo"), Cow::Borrowed("bar"));
    const BODY_FIELD_ID: Option<Cow<'_, str>> = Some(Cow::Borrowed("id"));
    const BODY_FIELD_DESC: Option<Cow<'_, str>> = Some(Cow::Borrowed("desc"));
    const BODY_FIELD_ENC: ContentEncoding = ContentEncoding::SevenBit;
    const BODY_FIELD_OCTETS: u32 = 1337;

    fn mock_body_text() -> (String, BodyStructure<'static>) {
        (
            format!(r#"("TEXT" "PLAIN" {BODY_FIELDS} 42)"#),
            BodyStructure::Text {
                common: BodyContentCommon {
                    ty: ContentType {
                        ty: Cow::Borrowed("TEXT"),
                        subtype: Cow::Borrowed("PLAIN"),
                        params: Some(vec![BODY_FIELD_PARAM_PAIR]),
                    },
                    disposition: None,
                    language: None,
                    location: None,
                },
                other: BodyContentSinglePart {
                    md5: None,
                    transfer_encoding: BODY_FIELD_ENC,
                    octets: BODY_FIELD_OCTETS,
                    id: BODY_FIELD_ID,
                    description: BODY_FIELD_DESC,
                },
                lines: 42,
                extension: None,
            },
        )
    }

    #[test]
    fn test_body_param_data() {
        assert_matches!(body_param(br#"NIL"#), Ok((EMPTY, None)));

        assert_matches!(
            body_param(br#"("foo" "bar")"#),
            Ok((EMPTY, Some(param))) => {
                assert_eq!(param, vec![(Cow::Borrowed("foo"), Cow::Borrowed("bar"))]);
            }
        );
    }

    #[test]
    fn test_body_lang_data() {
        assert_matches!(
            body_lang(br#""bob""#),
            Ok((EMPTY, Some(langs))) => {
                assert_eq!(langs, vec!["bob"]);
            }
        );

        assert_matches!(
            body_lang(br#"("one" "two")"#),
            Ok((EMPTY, Some(langs))) => {
                assert_eq!(langs, vec!["one", "two"]);
            }
        );

        assert_matches!(body_lang(br#"NIL"#), Ok((EMPTY, None)));
    }

    #[test]
    fn test_body_extension_data() {
        assert_matches!(
            BodyExtension::parse(br#""blah""#),
            Ok((EMPTY, BodyExtension::Str(Some(Cow::Borrowed("blah")))))
        );

        assert_matches!(
            BodyExtension::parse(br#"NIL"#),
            Ok((EMPTY, BodyExtension::Str(None)))
        );

        assert_matches!(
            BodyExtension::parse(br#"("hello")"#),
            Ok((EMPTY, BodyExtension::List(list))) => {
                assert_eq!(list, vec![BodyExtension::Str(Some(Cow::Borrowed("hello")))]);
            }
        );

        assert_matches!(
            BodyExtension::parse(br#"(1337)"#),
            Ok((EMPTY, BodyExtension::List(list))) => {
                assert_eq!(list, vec![BodyExtension::Num(1337)]);
            }
        );
    }

    #[test]
    fn test_body_disposition_data() {
        assert_matches!(body_disposition(br#"NIL"#), Ok((EMPTY, None)));

        assert_matches!(
            body_disposition(br#"("attachment" ("FILENAME" "pages.pdf"))"#),
            Ok((EMPTY, Some(disposition))) => {
                assert_eq!(disposition, ContentDisposition {
                    ty: Cow::Borrowed("attachment"),
                    params: Some(vec![
                        (Cow::Borrowed("FILENAME"), Cow::Borrowed("pages.pdf"))
                    ])
                });
            }
        );
    }

    // Apple iCloud sends NIL here, which the grammar does not allow.
    #[test]
    fn test_body_encoding_nil_is_seven_bit() {
        assert_matches!(
            ContentEncoding::parse(br"NIL"),
            Ok((EMPTY, ContentEncoding::SevenBit))
        );
    }

    // The whole response has to survive it, not just the field.
    #[test]
    fn test_body_structure_multipart_with_nil_encoding() {
        const BODY: &[u8] = br#"(("text" "plain" ("CHARSET" "UTF-8") NIL NIL NIL 1694 51 NIL NIL NIL NIL)("text" "html" ("CHARSET" "UTF-8") NIL NIL "quoted-printable" 5750 77 NIL NIL NIL NIL) "alternative" ("BOUNDARY" "94eb2c1235681e93cc0568edba59") NIL NIL NIL)"#;

        assert_matches!(
            BodyStructure::parse(BODY),
            Ok((EMPTY, BodyStructure::Multipart { bodies, .. })) => {
                assert_eq!(bodies.len(), 2);
                assert_matches!(
                    &bodies[0],
                    BodyStructure::Text { other, .. } => {
                        assert_eq!(other.transfer_encoding, ContentEncoding::SevenBit);
                    }
                );
            }
        );
    }

    #[test]
    fn test_body_structure_text() {
        let (body_str, body_struct) = mock_body_text();

        assert_matches!(
            BodyStructure::parse(body_str.as_bytes()),
            Ok((_, text)) => {
                assert_eq!(text, body_struct);
            }
        );
    }

    #[test]
    fn test_body_structure_text_with_ext() {
        let body_str = format!(r#"("TEXT" "PLAIN" {BODY_FIELDS} 42 NIL NIL NIL NIL)"#);
        let (_, text_body_struct) = mock_body_text();

        assert_matches!(
            BodyStructure::parse(body_str.as_bytes()),
            Ok((_, text)) => {
                assert_eq!(text, text_body_struct)
            }
        );
    }

    #[test]
    fn test_body_structure_basic() {
        const BODY: &[u8] = br#"("APPLICATION" "PDF" ("NAME" "pages.pdf") NIL NIL "BASE64" 38838 NIL ("attachment" ("FILENAME" "pages.pdf")) NIL NIL)"#;

        assert_matches!(
            BodyStructure::parse(BODY),
            Ok((_, basic)) => {
                assert_eq!(basic, BodyStructure::Basic {
                    common: BodyContentCommon {
                        ty: ContentType {
                            ty: Cow::Borrowed("APPLICATION"),
                            subtype: Cow::Borrowed("PDF"),
                            params: Some(vec![(Cow::Borrowed("NAME"), Cow::Borrowed("pages.pdf"))])
                        },
                        disposition: Some(ContentDisposition {
                            ty: Cow::Borrowed("attachment"),
                            params: Some(vec![(Cow::Borrowed("FILENAME"), Cow::Borrowed("pages.pdf"))])
                        }),
                        language: None,
                        location: None,
                    },
                    other: BodyContentSinglePart {
                        transfer_encoding: ContentEncoding::Base64,
                        octets: 38838,
                        id: None,
                        md5: None,
                        description: None,
                    },
                    extension: None,
                })
            }
        );
    }

    #[test]
    fn test_body_structure_message() {
        let (text_body_str, _) = mock_body_text();
        let envelope_str = r#"("Wed, 17 Jul 1996 02:23:25 -0700 (PDT)" "IMAP4rev1 WG mtg summary and minutes" (("Terry Gray" NIL "gray" "cac.washington.edu")) (("Terry Gray" NIL "gray" "cac.washington.edu")) (("Terry Gray" NIL "gray" "cac.washington.edu")) ((NIL NIL "imap" "cac.washington.edu")) ((NIL NIL "minutes" "CNRI.Reston.VA.US") ("John Klensin" NIL "KLENSIN" "MIT.EDU")) NIL NIL "<B27397-0100000@cac.washington.edu>")"#;
        let body_str =
            format!(r#"("MESSAGE" "RFC822" {BODY_FIELDS} {envelope_str} {text_body_str} 42)"#);

        assert_matches!(
            BodyStructure::parse(body_str.as_bytes()),
            Ok((_, BodyStructure::Message { .. }))
        );
    }

    // `many1` ends a multipart's children at the first one that does not parse,
    // and the remaining input must then be the multipart's subtype.
    #[test]
    fn test_body_structure_multipart_ends_children_at_first_non_body() {
        let (text, _) = mock_body_text();
        let body_str = format!(r#"({text}{text} "MIXED")"#);
        assert_matches!(
            BodyStructure::parse(body_str.as_bytes()),
            Ok((EMPTY, BodyStructure::Multipart { bodies, .. })) => assert_eq!(bodies.len(), 2)
        );

        // a malformed second child is not skipped over
        let body_str = format!(r#"({text}("TEXT" "PLAIN" oops) "MIXED")"#);
        assert_matches!(
            BodyStructure::parse(body_str.as_bytes()),
            Err(nom::Err::Error(_))
        );
    }

    // A text part without a line count is not a text body, but is a valid basic one.
    #[test]
    fn test_body_structure_text_without_lines_is_basic() {
        let body_str = format!(r#"("TEXT" "PLAIN" {BODY_FIELDS})"#);
        assert_matches!(
            BodyStructure::parse(body_str.as_bytes()),
            Ok((EMPTY, BodyStructure::Basic { .. }))
        );
    }

    fn nested_multiparts(depth: usize) -> String {
        let (mut body, _) = mock_body_text();
        for _ in 0..depth {
            body = format!(r#"({body} "MIXED")"#);
        }
        body
    }

    fn nested_messages(depth: usize) -> String {
        const ENVELOPE: &str = "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";
        let (mut body, _) = mock_body_text();
        for _ in 0..depth {
            body = format!(r#"("MESSAGE" "RFC822" {BODY_FIELDS} {ENVELOPE} {body} 42)"#);
        }
        body
    }

    fn text_with_nested_extension(depth: usize) -> String {
        format!(
            r#"("TEXT" "PLAIN" {BODY_FIELDS} 42 NIL NIL NIL NIL {}1{})"#,
            "(".repeat(depth),
            ")".repeat(depth)
        )
    }

    fn assert_nesting_limit(build: fn(usize) -> String) {
        let at_limit = build(MAX_NESTING_DEPTH);
        assert_matches!(BodyStructure::parse(at_limit.as_bytes()), Ok((EMPTY, _)));

        let too_deep = build(MAX_NESTING_DEPTH + 1);
        assert_matches!(
            BodyStructure::parse(too_deep.as_bytes()),
            Err(nom::Err::Failure(e)) => assert_eq!(e.code, ErrorKind::TooLarge)
        );
    }

    #[test]
    fn test_body_structure_multipart_nesting_limit() {
        assert_nesting_limit(nested_multiparts);
    }

    #[test]
    fn test_body_structure_message_nesting_limit() {
        assert_nesting_limit(nested_messages);
    }

    #[test]
    fn test_body_extension_nesting_limit() {
        assert_nesting_limit(text_with_nested_extension);
    }

    // Multipart and message levels count towards the same limit.
    #[test]
    fn test_body_structure_mixed_nesting_limit() {
        const ENVELOPE: &str = "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";
        let build = |depth: usize| {
            let (mut body, _) = mock_body_text();
            for level in 0..depth {
                body = if level % 2 == 0 {
                    format!(r#"({body} "MIXED")"#)
                } else {
                    format!(r#"("MESSAGE" "RFC822" {BODY_FIELDS} {ENVELOPE} {body} 42)"#)
                };
            }
            body
        };
        let at_limit = build(MAX_NESTING_DEPTH);
        assert_matches!(BodyStructure::parse(at_limit.as_bytes()), Ok((EMPTY, _)));
        let too_deep = build(MAX_NESTING_DEPTH + 1);
        assert_matches!(
            BodyStructure::parse(too_deep.as_bytes()),
            Err(nom::Err::Failure(_))
        );
    }

    // Streaming callers read more data on `Incomplete`, so running out of input
    // must stay `Incomplete` and a limit hit must never be reported as one.
    #[test]
    fn test_body_structure_truncated_input_is_incomplete() {
        for body in [
            nested_multiparts(5),
            nested_messages(5),
            text_with_nested_extension(5),
        ] {
            for end in 1..body.len() {
                assert_matches!(
                    BodyStructure::parse(&body.as_bytes()[..end]),
                    Err(nom::Err::Incomplete(_)),
                    "truncated at {end}: {:?}",
                    &body[..end]
                );
            }
        }
    }

    #[test]
    fn test_body_structure_multipart() {
        let (text_body_str1, text_body_struct1) = mock_body_text();
        let (text_body_str2, text_body_struct2) = mock_body_text();
        let body_str =
            format!(r#"({text_body_str1}{text_body_str2} "ALTERNATIVE" NIL NIL NIL NIL)"#);

        assert_matches!(
            BodyStructure::parse(body_str.as_bytes()),
            Ok((_, multipart)) => {
                assert_eq!(multipart, BodyStructure::Multipart {
                    common: BodyContentCommon {
                        ty: ContentType {
                            ty: Cow::Borrowed("MULTIPART"),
                            subtype: Cow::Borrowed("ALTERNATIVE"),
                            params: None
                        },
                        language: None,
                        location: None,
                        disposition: None,
                    },
                    bodies: vec![
                        text_body_struct1,
                        text_body_struct2,
                    ],
                    extension: None
                });
            }
        );
    }
}
