use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    character::streaming::char,
    combinator::{map, opt},
    multi::many1,
    sequence::{delimited, preceded, tuple},
    IResult,
};
use std::borrow::Cow;

use crate::{
    parser::{core::*, rfc3501::envelope},
    types::*,
};

// body-fields     = body-fld-param SP body-fld-id SP body-fld-desc SP
//                   body-fld-enc SP body-fld-octets
fn body_fields(i: &[u8]) -> IResult<&[u8], BodyFields<'_>> {
    let (i, (param, _, id, _, description, _, transfer_encoding, _, octets)) = tuple((
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
        body_encoding,
        tag(" "),
        number,
    ))(i)?;
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

// body-ext-1part  = body-fld-md5 [SP body-fld-dsp [SP body-fld-lang
//                   [SP body-fld-loc *(SP body-extension)]]]
//                     ; MUST NOT be returned on non-extensible
//                     ; "BODY" fetch
fn body_ext_1part(i: &[u8]) -> IResult<&[u8], BodyExt1Part<'_>> {
    let (i, (md5, disposition, language, location, extension)) = tuple((
        // Per RFC 1864, MD5 values are base64-encoded
        opt_opt(preceded(tag(" "), nstring_utf8)),
        opt_opt(preceded(tag(" "), body_disposition)),
        opt_opt(preceded(tag(" "), body_lang)),
        // Location appears to reference a URL, which by RFC 1738 (section 2.2) should be ASCII
        opt_opt(preceded(tag(" "), nstring_utf8)),
        opt(preceded(tag(" "), body_extension)),
    ))(i)?;
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

// body-ext-mpart  = body-fld-param [SP body-fld-dsp [SP body-fld-lang
//                   [SP body-fld-loc *(SP body-extension)]]]
//                     ; MUST NOT be returned on non-extensible
//                     ; "BODY" fetch
fn body_ext_mpart(i: &[u8]) -> IResult<&[u8], BodyExtMPart<'_>> {
    let (i, (param, disposition, language, location, extension)) = tuple((
        opt_opt(preceded(tag(" "), body_param)),
        opt_opt(preceded(tag(" "), body_disposition)),
        opt_opt(preceded(tag(" "), body_lang)),
        // Location appears to reference a URL, which by RFC 1738 (section 2.2) should be ASCII
        opt_opt(preceded(tag(" "), nstring_utf8)),
        opt(preceded(tag(" "), body_extension)),
    ))(i)?;
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

// RFC 3501 defines `body-fld-enc` as a string, never NIL, but some servers send
// NIL for a part with no Content-Transfer-Encoding header (seen on Apple iCloud;
// imap-codec records the same from maddy). RFC 2045 s6.1 defaults that to 7bit.
fn body_encoding(i: &[u8]) -> IResult<&[u8], ContentEncoding<'_>> {
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
    ))(i)
}

fn body_lang(i: &[u8]) -> IResult<&[u8], Option<Vec<Cow<'_, str>>>> {
    alt((
        // body language seems to refer to RFC 3066 language tags, which should be ASCII-only
        map(nstring_utf8, |v| v.map(|s| vec![s])),
        map(parenthesized_nonempty_list(string_utf8), Option::from),
    ))(i)
}

fn body_param(i: &[u8]) -> IResult<&[u8], BodyParams<'_>> {
    alt((
        map(nil, |_| None),
        map(
            parenthesized_nonempty_list(map(
                tuple((string_utf8, tag(" "), string_utf8)),
                |(key, _, val)| (key, val),
            )),
            Option::from,
        ),
    ))(i)
}

fn body_extension(i: &[u8]) -> IResult<&[u8], BodyExtension<'_>> {
    alt((
        map(number, BodyExtension::Num),
        // Cannot find documentation on character encoding for body extension values.
        // So far, assuming UTF-8 seems fine, please report if you run into issues here.
        map(nstring_utf8, BodyExtension::Str),
        map(
            parenthesized_nonempty_list(body_extension),
            BodyExtension::List,
        ),
    ))(i)
}

fn body_disposition(i: &[u8]) -> IResult<&[u8], Option<ContentDisposition<'_>>> {
    alt((
        map(nil, |_| None),
        paren_delimited(map(
            tuple((string_utf8, tag(" "), body_param)),
            |(ty, _, params)| Some(ContentDisposition { ty, params }),
        )),
    ))(i)
}

fn body_type_basic(i: &[u8]) -> IResult<&[u8], BodyStructure<'_>> {
    map(
        tuple((
            string_utf8,
            tag(" "),
            string_utf8,
            tag(" "),
            body_fields,
            body_ext_1part,
        )),
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
    )(i)
}

fn body_type_text(i: &[u8]) -> IResult<&[u8], BodyStructure<'_>> {
    map(
        tuple((
            tag_no_case("\"TEXT\""),
            tag(" "),
            string_utf8,
            tag(" "),
            body_fields,
            tag(" "),
            number,
            body_ext_1part,
        )),
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
    )(i)
}

fn body_type_message(i: &[u8]) -> IResult<&[u8], BodyStructure<'_>> {
    map(
        tuple((
            tag_no_case("\"MESSAGE\" \"RFC822\""),
            tag(" "),
            body_fields,
            tag(" "),
            envelope,
            tag(" "),
            body,
            tag(" "),
            number,
            body_ext_1part,
        )),
        |(_, _, fields, _, envelope, _, body, _, lines, ext)| BodyStructure::Message {
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
    )(i)
}

fn body_type_multipart(i: &[u8]) -> IResult<&[u8], BodyStructure<'_>> {
    map(
        tuple((many1(body), tag(" "), string_utf8, body_ext_mpart)),
        |(bodies, _, subtype, ext)| BodyStructure::Multipart {
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
    )(i)
}

pub(crate) fn body(i: &[u8]) -> IResult<&[u8], BodyStructure<'_>> {
    paren_delimited(alt((
        body_type_text,
        body_type_message,
        body_type_basic,
        body_type_multipart,
    )))(i)
}

pub(crate) fn msg_att_body_structure(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(tuple((tag_no_case("BODYSTRUCTURE "), body)), |(_, body)| {
        AttributeValue::BodyStructure(body)
    })(i)
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
            body_extension(br#""blah""#),
            Ok((EMPTY, BodyExtension::Str(Some(Cow::Borrowed("blah")))))
        );

        assert_matches!(
            body_extension(br#"NIL"#),
            Ok((EMPTY, BodyExtension::Str(None)))
        );

        assert_matches!(
            body_extension(br#"("hello")"#),
            Ok((EMPTY, BodyExtension::List(list))) => {
                assert_eq!(list, vec![BodyExtension::Str(Some(Cow::Borrowed("hello")))]);
            }
        );

        assert_matches!(
            body_extension(br#"(1337)"#),
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
            body_encoding(br"NIL"),
            Ok((EMPTY, ContentEncoding::SevenBit))
        );
    }

    // The whole response has to survive it, not just the field.
    #[test]
    fn test_body_structure_multipart_with_nil_encoding() {
        const BODY: &[u8] = br#"(("text" "plain" ("CHARSET" "UTF-8") NIL NIL NIL 1694 51 NIL NIL NIL NIL)("text" "html" ("CHARSET" "UTF-8") NIL NIL "quoted-printable" 5750 77 NIL NIL NIL NIL) "alternative" ("BOUNDARY" "94eb2c1235681e93cc0568edba59") NIL NIL NIL)"#;

        assert_matches!(
            body(BODY),
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
            body(body_str.as_bytes()),
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
            body(body_str.as_bytes()),
            Ok((_, text)) => {
                assert_eq!(text, text_body_struct)
            }
        );
    }

    #[test]
    fn test_body_structure_basic() {
        const BODY: &[u8] = br#"("APPLICATION" "PDF" ("NAME" "pages.pdf") NIL NIL "BASE64" 38838 NIL ("attachment" ("FILENAME" "pages.pdf")) NIL NIL)"#;

        assert_matches!(
            body(BODY),
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
            body(body_str.as_bytes()),
            Ok((_, BodyStructure::Message { .. }))
        );
    }

    #[test]
    fn test_body_structure_multipart() {
        let (text_body_str1, text_body_struct1) = mock_body_text();
        let (text_body_str2, text_body_struct2) = mock_body_text();
        let body_str =
            format!(r#"({text_body_str1}{text_body_str2} "ALTERNATIVE" NIL NIL NIL NIL)"#);

        assert_matches!(
            body(body_str.as_bytes()),
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
