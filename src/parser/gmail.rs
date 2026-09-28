use std::borrow::Cow;

use nom::branch::alt;
use nom::bytes::streaming::tag_no_case;
use nom::combinator::map;
use nom::sequence::preceded;
use nom::{IResult, Parser};

use crate::{AttributeValue, MailboxDatum};

use super::core::{number_64, parenthesized_list, quoted_utf8};
use super::rfc3501::flag;

pub(crate) fn gmail_label_list(i: &[u8]) -> IResult<&[u8], Vec<Cow<'_, str>>> {
    preceded(
        tag_no_case("X-GM-LABELS "),
        parenthesized_list(alt((map(flag, Cow::Borrowed), quoted_utf8))),
    )
    .parse(i)
}

pub(crate) fn msg_att_gmail_labels(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(gmail_label_list, AttributeValue::GmailLabels).parse(i)
}

pub(crate) fn mailbox_data_gmail_labels(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(gmail_label_list, MailboxDatum::GmailLabels).parse(i)
}

pub(crate) fn gmail_msgid(i: &[u8]) -> IResult<&[u8], u64> {
    preceded(tag_no_case("X-GM-MSGID "), number_64).parse(i)
}

pub(crate) fn msg_att_gmail_msgid(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(gmail_msgid, AttributeValue::GmailMsgId).parse(i)
}

pub(crate) fn mailbox_data_gmail_msgid(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(gmail_msgid, MailboxDatum::GmailMsgId).parse(i)
}

pub(crate) fn gmail_thrid(i: &[u8]) -> IResult<&[u8], u64> {
    preceded(tag_no_case("X-GM-THRID "), number_64).parse(i)
}

pub(crate) fn msg_att_gmail_thrid(i: &[u8]) -> IResult<&[u8], AttributeValue<'_>> {
    map(gmail_thrid, AttributeValue::GmailThrId).parse(i)
}

pub(crate) fn mailbox_data_gmail_thrid(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(gmail_thrid, MailboxDatum::GmailThrId).parse(i)
}

#[cfg(test)]
mod tests {
    use crate::types::*;
    #[test]
    fn test_gmail_labels() {
        let env = br#"X-GM-LABELS (\Inbox \Sent Important "Muy Importante") "#;
        match super::msg_att_gmail_labels(env) {
            Ok((_, AttributeValue::GmailLabels(labels))) => {
                println!("{labels:?}");
                assert_eq!(
                    ["\\Inbox", "\\Sent", "Important", "Muy Importante"].to_vec(),
                    labels
                );
            }
            rsp => {
                let e = rsp.unwrap_err();
                if let nom::Err::Error(i) = &e {
                    println!("{:?}", std::str::from_utf8(i.input));
                }
                panic!("unexpected response {e:?}");
            }
        }
    }

    #[test]
    fn test_gmail_msgid() {
        let env = br#"X-GM-MSGID 1278455344230334865 "#;
        match super::msg_att_gmail_msgid(env) {
            Ok((_, AttributeValue::GmailMsgId(msgid))) => {
                println!("{msgid:?}");
                assert_eq!(1278455344230334865u64, msgid);
            }
            rsp => {
                let e = rsp.unwrap_err();
                if let nom::Err::Error(i) = &e {
                    println!("{:?}", std::str::from_utf8(i.input));
                }
                panic!("unexpected response {e:?}");
            }
        }
    }

    #[test]
    fn test_gmail_thrid() {
        let env = br#"X-GM-THRID 1278455344230334865 "#;
        match super::msg_att_gmail_thrid(env) {
            Ok((_, AttributeValue::GmailThrId(thrid))) => {
                println!("{thrid:?}");
                assert_eq!(1278455344230334865, thrid);
            }
            rsp => {
                let e = rsp.unwrap_err();
                if let nom::Err::Error(i) = &e {
                    println!("{:?}", std::str::from_utf8(i.input));
                }
                panic!("unexpected response {e:?}");
            }
        }
    }
}
