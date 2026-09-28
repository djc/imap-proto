use std::borrow::Cow;
use std::collections::HashMap;

use nom::{branch::alt, IResult, Parser};

pub mod builders;

pub mod core;
use crate::core::to_owned_cow;

pub mod bodystructure;

pub mod gmail;

pub mod rfc2087;
pub use rfc2087::{Quota, QuotaResource, QuotaResourceName, QuotaRoot};

pub mod rfc2971;

pub mod rfc3501;
pub use rfc3501::body::{MessageSection, SectionPath};
pub use rfc3501::body_structure::{
    BodyContentCommon, BodyContentSinglePart, BodyExt1Part, BodyExtMPart, BodyExtension,
    BodyFields, BodyParams, BodyStructure, ContentDisposition, ContentEncoding, ContentType,
};
pub use rfc3501::{
    Address, AttributeValue, Capability, Envelope, MailboxDatum, MailboxListData, NameAttribute,
    Outcome, RequestId, ResponseCode, Status, StatusAttribute,
};

pub mod rfc4314;
pub use rfc4314::{Acl, AclEntry, AclRight, ListRights, MyRights};

pub mod rfc4315;
pub use rfc4315::UidSetMember;

pub mod rfc4551;

pub mod rfc5161;

pub mod rfc5256;

pub mod rfc5464;
pub use rfc5464::Metadata;

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
    pub fn parse(msg: &'a [u8]) -> ParseResult<'a> {
        alt((
            rfc3501::continue_req,
            rfc3501::response_data,
            rfc3501::response_tagged,
        ))
        .parse(msg)
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

pub type ParseResult<'a> = IResult<&'a [u8], Response<'a>>;
