use std::borrow::Cow;
use std::collections::HashMap;

use nom::{branch::alt, IResult, Parser};

use rfc2087::{Quota, QuotaRoot};
use rfc3501::{AttributeValue, Capability, MailboxDatum, Outcome, RequestId, Status};
use rfc4314::{Acl, ListRights, MyRights};

use crate::parser::core::to_owned_cow;

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

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Response<'a> {
    Capabilities(Vec<Capability<'a>>),
    Continue(Outcome<'a>),
    Done {
        tag: RequestId,
        status: Status,
        outcome: Outcome<'a>,
    },
    Data {
        status: Status,
        outcome: Outcome<'a>,
    },
    Expunge(u32),
    Vanished {
        earlier: bool,
        uids: Vec<std::ops::RangeInclusive<u32>>,
    },
    Fetch(u32, Vec<AttributeValue<'a>>),
    MailboxData(MailboxDatum<'a>),
    Quota(Quota<'a>),
    QuotaRoot(QuotaRoot<'a>),
    Id(Option<HashMap<Cow<'a, str>, Cow<'a, str>>>),
    Acl(Acl<'a>),
    ListRights(ListRights<'a>),
    MyRights(MyRights<'a>),
}

impl<'a> Response<'a> {
    pub fn from_bytes(buf: &'a [u8]) -> crate::ParseResult<'a> {
        crate::parser::parse_response(buf)
    }

    pub fn into_owned(self) -> Response<'static> {
        match self {
            Response::Capabilities(capabilities) => Response::Capabilities(
                capabilities
                    .into_iter()
                    .map(Capability::into_owned)
                    .collect(),
            ),
            Response::Continue(outcome) => Response::Continue(outcome.into_owned()),
            Response::Done {
                tag,
                status,
                outcome,
            } => Response::Done {
                tag,
                status,
                outcome: outcome.into_owned(),
            },
            Response::Data { status, outcome } => Response::Data {
                status,
                outcome: outcome.into_owned(),
            },
            Response::Expunge(seq) => Response::Expunge(seq),
            Response::Vanished { earlier, uids } => Response::Vanished { earlier, uids },
            Response::Fetch(seq, attrs) => Response::Fetch(
                seq,
                attrs.into_iter().map(AttributeValue::into_owned).collect(),
            ),
            Response::MailboxData(datum) => Response::MailboxData(datum.into_owned()),
            Response::Quota(quota) => Response::Quota(quota.into_owned()),
            Response::QuotaRoot(quota_root) => Response::QuotaRoot(quota_root.into_owned()),
            Response::Id(map) => Response::Id(map.map(|m| {
                m.into_iter()
                    .map(|(k, v)| (to_owned_cow(k), to_owned_cow(v)))
                    .collect()
            })),
            Response::Acl(acl_list) => Response::Acl(acl_list.into_owned()),
            Response::ListRights(rights) => Response::ListRights(rights.into_owned()),
            Response::MyRights(rights) => Response::MyRights(rights.into_owned()),
        }
    }
}

pub fn parse_response(msg: &[u8]) -> ParseResult<'_> {
    alt((
        rfc3501::continue_req,
        rfc3501::response_data,
        rfc3501::response_tagged,
    ))
    .parse(msg)
}

pub type ParseResult<'a> = IResult<&'a [u8], Response<'a>>;
